#include "secured_socket.h"
#include <cassert>

namespace ag::dns {

enum SecuredSocket::State : int {
    SS_IDLE,
    SS_CONNECTING_SOCKET,
    SS_CONNECTING_TLS,
    SS_CONNECTED,
};

SecuredSocket::SecuredSocket(SocketFactory::SocketPtr underlying_socket, const CertificateVerifier *cert_verifier,
        SocketFactory::SecureSocketParameters secure_parameters)
        : Socket(__func__,
                {
                        .proto = underlying_socket->get_protocol(),
                },
                {})
        , m_state(SS_IDLE)
        , m_underlying_socket(std::move(underlying_socket))
        , m_codec(cert_verifier, secure_parameters.session_cache, std::move(secure_parameters.fingerprints))
        , m_sni(std::move(secure_parameters.server_name))
        , m_alpn(std::move(secure_parameters.alpn))
        , m_enable_pq(secure_parameters.enable_post_quantum)
        , m_log(__func__) {
    m_shutdown_guard = std::make_shared<bool>(true);
}

std::optional<std::string> SecuredSocket::get_alpn() const {
    return m_codec.get_alpn_selected();
}

std::optional<evutil_socket_t> SecuredSocket::get_fd() const {
    return m_underlying_socket->get_fd();
}

Error<SocketError> SecuredSocket::connect(ConnectParameters params) {
    assert(m_state == SS_IDLE);
    auto err = m_underlying_socket->connect(this->make_underlying_connect_parameters(params));
    if (!err) {
        err = this->set_callbacks(params.callbacks);
    }
    if (!err) {
        m_state = SS_CONNECTING_SOCKET;
    }
    return err;
}

Error<SocketError> SecuredSocket::send(Uint8View data) {
    while (!data.empty()) {
        TlsCodec::WriteDecryptedResult wr_result = m_codec.write_decrypted(data);
        if (wr_result.has_error()) {
            return make_error(SocketError::AE_TLS_ERROR, wr_result.error());
        }

        if (auto err = this->flush_pending_encrypted_data()) {
            return err;
        }

        data.remove_prefix(wr_result->num);
    }

    return {};
}

bool SecuredSocket::set_timeout(Micros timeout) {
    return m_underlying_socket->set_timeout(timeout);
}

Error<SocketError> SecuredSocket::set_callbacks(Callbacks cbx) {
    std::scoped_lock l(m_callbacks.mtx);
    m_callbacks.val = cbx;
    return {};
}

void SecuredSocket::on_connected(void *arg) {
    auto *self = (SecuredSocket *) arg;
    assert(self->m_state == SS_CONNECTING_SOCKET);

    if (auto err = self->m_codec.connect(self->m_sni, self->m_alpn, self->m_enable_pq)) {
        if (Callbacks cbx = self->get_callbacks(); cbx.on_close != nullptr) {
            cbx.on_close(cbx.arg, make_error(SocketError::AE_TLS_ERROR, err));
            return;
        }
    }

    if (auto err = self->flush_pending_encrypted_data()) {
        if (Callbacks cbx = self->get_callbacks(); cbx.on_close != nullptr) {
            cbx.on_close(cbx.arg, err);
            return;
        }
    }

    self->m_state = SS_CONNECTING_TLS;
}

void SecuredSocket::on_read(void *arg, Uint8View data) {
    auto *self = (SecuredSocket *) arg;

    if (auto err = self->m_codec.recv_encrypted(data)) {
        if (Callbacks cbx = self->get_callbacks(); cbx.on_close != nullptr) {
            cbx.on_close(cbx.arg, make_error(SocketError::AE_TLS_ERROR, err));
            return;
        }
    }

    if (auto err = self->flush_pending_encrypted_data()) {
        if (Callbacks cbx = self->get_callbacks(); cbx.on_close != nullptr) {
            cbx.on_close(cbx.arg, err);
            return;
        }
    }

    if (self->m_state == SS_CONNECTING_TLS) {
        if (!self->m_codec.is_connected()) {
            return;
        }
        self->m_state = SS_CONNECTED;
        if (Callbacks cbx = self->get_callbacks(); cbx.on_connected != nullptr) {
            cbx.on_connected(cbx.arg);
        }
    }

    bool want_read = self->m_codec.want_read_decrypted();
    while (want_read) {
        TlsCodec::Chunk decrypted_chunk;

        if (std::unique_lock l{self->m_callbacks.mtx}) {
            Callbacks cbx = self->m_callbacks.val;
            if (cbx.on_read == nullptr) {
                break;
            }

            TlsCodec::ReadDecryptedResult r = self->m_codec.read_decrypted();
            if (r.has_error()) {
                if (cbx.on_close != nullptr) {
                    l.unlock();
                    cbx.on_close(cbx.arg, make_error(SocketError::AE_TLS_ERROR, r.error()));
                    // on_close might have deleted `self`
                }
                return;
            }

            want_read = self->m_codec.want_read_decrypted();
            decrypted_chunk = std::move(r.value());
        }

        if (Callbacks cbx = self->get_callbacks(); cbx.on_read != nullptr) {
            std::weak_ptr<bool> shutdown_guard = self->m_shutdown_guard;
            cbx.on_read(cbx.arg, {decrypted_chunk.data.data(), decrypted_chunk.data.size()});
            if (shutdown_guard.expired()) {
                return;
            }
        } else {
            if (!decrypted_chunk.data.empty()) {
                // @todo: buffer and re-raise it later if needed
                dbglog(self->m_log, "{} bytes were dropped", decrypted_chunk.data.size());
            }
        }
    }
}

void SecuredSocket::on_close(void *arg, Error<SocketError> error) {
    auto *self = (SecuredSocket *) arg;
    if (Callbacks cbx = self->get_callbacks(); cbx.on_close != nullptr) {
        cbx.on_close(cbx.arg, std::move(error));
    }
}

Socket::ConnectParameters SecuredSocket::make_underlying_connect_parameters(ConnectParameters &params) const {
    return {
            params.loop,
            params.peer,
            {on_connected, on_read, on_close, (void *) this},
            params.timeout,
    };
}

Socket::Callbacks SecuredSocket::get_callbacks() {
    std::scoped_lock l(m_callbacks.mtx);
    return m_callbacks.val;
}

Error<SocketError> SecuredSocket::flush_pending_encrypted_data() {
    while (m_codec.want_send_encrypted()) {
        TlsCodec::SendEncryptedResult send_result = m_codec.send_encrypted();
        if (send_result.has_error()) {
            return make_error(SocketError::AE_TLS_ERROR, send_result.error());
        }

        const auto &chunk = send_result.value();
        if (auto err = m_underlying_socket->send({chunk.data.data(), chunk.data.size()})) {
            return err;
        }
    }

    return {};
}

} // namespace ag::dns
