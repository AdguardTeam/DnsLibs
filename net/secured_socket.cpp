#include "secured_socket.h"
#include <cassert>

namespace ag {

enum SecuredSocket::State : int {
    SS_IDLE,
    SS_CONNECTING_SOCKET,
    SS_CONNECTING_TLS,
    SS_CONNECTED,
};

SecuredSocket::SecuredSocket(SocketFactory::SocketPtr underlying_socket, const CertificateVerifier *cert_verifier,
        SocketFactory::SecureSocketParameters secure_parameters)
        : Socket(__func__, {}, {})
        , m_state(SS_IDLE)
        , m_underlying_socket(std::move(underlying_socket))
        , m_codec(cert_verifier, secure_parameters.session_cache)
        , m_sni(std::move(secure_parameters.server_name))
        , m_alpn(std::move(secure_parameters.alpn))
        , m_log(__func__) {
}

std::optional<evutil_socket_t> SecuredSocket::get_fd() const {
    return m_underlying_socket->get_fd();
}

std::optional<Socket::Error> SecuredSocket::connect(ConnectParameters params) {
    std::optional err = m_underlying_socket->connect(this->make_underlying_connect_parameters(params));
    if (!err.has_value()) {
        err = this->set_callbacks(params.callbacks);
    }
    if (!err.has_value()) {
        m_state = SS_CONNECTING_SOCKET;
    }
    return err;
}

std::optional<Socket::Error> SecuredSocket::send(Uint8View data) {
    while (!data.empty()) {
        TlsCodec::WriteDecryptedResult wr_result = m_codec.write_decrypted(data);
        if (auto *err = std::get_if<TlsCodec::Error>(&wr_result); err != nullptr) {
            return {{-1, std::move(err->description)}};
        }

        if (std::optional err = this->flush_pending_encrypted_data(); err.has_value()) {
            return err;
        }

        data.remove_prefix(std::get<TlsCodec::DecryptedBytesWritten>(wr_result).num);
    }

    return std::nullopt;
}

std::optional<Socket::Error> SecuredSocket::send_dns_packet(Uint8View data) {
    uint16_t length = htons(data.size());

    uint8_t buffer[sizeof(length) + data.size()];
    memcpy(buffer, (uint8_t *) &length, sizeof(length));
    memcpy(buffer + sizeof(length), data.data(), data.size());

    return this->send({buffer, sizeof(buffer)});
}

bool SecuredSocket::set_timeout(Micros timeout) {
    return m_underlying_socket->set_timeout(timeout);
}

std::optional<Socket::Error> SecuredSocket::set_callbacks(Callbacks cbx) {
    std::scoped_lock l(m_callbacks.mtx);
    m_callbacks.val = cbx;
    return std::nullopt;
}

void SecuredSocket::on_connected(void *arg) {
    auto *self = (SecuredSocket *) arg;
    assert(self->m_state == SS_CONNECTING_SOCKET);

    if (std::optional err = self->m_codec.connect(self->m_sni, self->m_alpn); err.has_value()) {
        if (Callbacks cbx = self->get_callbacks(); cbx.on_close != nullptr) {
            cbx.on_close(cbx.arg, {{-1, std::move(err->description)}});
            return;
        }
    }

    if (std::optional err = self->flush_pending_encrypted_data(); err.has_value()) {
        if (Callbacks cbx = self->get_callbacks(); cbx.on_close != nullptr) {
            cbx.on_close(cbx.arg, std::move(err));
            return;
        }
    }

    self->m_state = SS_CONNECTING_TLS;
}

void SecuredSocket::on_read(void *arg, Uint8View data) {
    auto *self = (SecuredSocket *) arg;

    if (std::optional err = self->m_codec.recv_encrypted(data); err.has_value()) {
        if (Callbacks cbx = self->get_callbacks(); cbx.on_close != nullptr) {
            cbx.on_close(cbx.arg, {{-1, std::move(err->description)}});
        }
    }

    if (std::optional err = self->flush_pending_encrypted_data(); err.has_value()) {
        if (Callbacks cbx = self->get_callbacks(); cbx.on_close != nullptr) {
            cbx.on_close(cbx.arg, std::move(err));
        }
    }

    if (self->m_state == SS_CONNECTING_TLS && self->m_codec.is_connected()) {
        self->m_state = SS_CONNECTED;
        if (Callbacks cbx = self->get_callbacks(); cbx.on_connected != nullptr) {
            cbx.on_connected(cbx.arg);
        }
    }

    while (self->m_codec.want_read_decrypted()) {
        TlsCodec::Chunk decrypted_chunk;

        {
            std::unique_lock l(self->m_callbacks.mtx);
            Callbacks cbx = self->m_callbacks.val;
            if (cbx.on_read == nullptr) {
                break;
            }

            TlsCodec::ReadDecryptedResult r = self->m_codec.read_decrypted();
            if (auto *err = std::get_if<TlsCodec::Error>(&r); err != nullptr) {
                if (cbx.on_close != nullptr) {
                    l.unlock();
                    cbx.on_close(cbx.arg, {{-1, std::move(err->description)}});
                    l.lock();
                    return;
                }
            }

            decrypted_chunk = std::move(std::get<TlsCodec::Chunk>(r));
        }

        if (Callbacks cbx = self->get_callbacks(); cbx.on_read != nullptr) {
            if (!decrypted_chunk.data.empty()) {
                // @todo: buffer and re-raise it later if needed
                dbglog(self->m_log, "{} bytes were dropped", decrypted_chunk.data.size());
            }
            cbx.on_read(cbx.arg, {decrypted_chunk.data.data(), decrypted_chunk.data.size()});
        }
    }
}

void SecuredSocket::on_close(void *arg, std::optional<Error> error) {
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

std::optional<Socket::Error> SecuredSocket::flush_pending_encrypted_data() {
    while (m_codec.want_send_encrypted()) {
        TlsCodec::SendEncryptedResult send_result = m_codec.send_encrypted();
        if (auto *err = std::get_if<TlsCodec::Error>(&send_result); err != nullptr) {
            return {{-1, std::move(err->description)}};
        }

        const auto &chunk = std::get<TlsCodec::Chunk>(send_result);
        if (auto err = m_underlying_socket->send({chunk.data.data(), chunk.data.size()}); err.has_value()) {
            return err;
        }
    }

    return std::nullopt;
}

} // namespace ag
