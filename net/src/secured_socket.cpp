#include <cassert>
#include "secured_socket.h"


using namespace ag;


enum secured_socket::state : int {
    SS_IDLE,
    SS_CONNECTING_SOCKET,
    SS_CONNECTING_TLS,
    SS_CONNECTED,
};


secured_socket::secured_socket(socket_factory::socket_ptr underlying_socket,
        const certificate_verifier *cert_verifier,
        socket_factory::secure_socket_parameters secure_parameters)
    : socket(__func__, {}, {})
    , state(SS_IDLE)
    , underlying_socket(std::move(underlying_socket))
    , codec(cert_verifier, secure_parameters.session_cache)
    , sni(std::move(secure_parameters.server_name))
    , alpn(std::move(secure_parameters.alpn))
    , log(__func__)
{}

std::optional<evutil_socket_t> secured_socket::get_fd() const {
    return this->underlying_socket->get_fd();
}

std::optional<socket::error> secured_socket::connect(connect_parameters params) {
    std::optional err = this->underlying_socket->connect(this->make_underlying_connect_parameters(params));
    if (!err.has_value()) {
        err = this->set_callbacks(params.callbacks);
    }
    if (!err.has_value()) {
        this->state = SS_CONNECTING_SOCKET;
    }
    return err;
}

std::optional<socket::error> secured_socket::send(Uint8View data) {
    while (!data.empty()) {
        tls_codec::write_decrypted_result wr_result = this->codec.write_decrypted(data);
        if (auto *err = std::get_if<tls_codec::error>(&wr_result); err != nullptr) {
            return { { -1, std::move(err->description) } };
        }

        if (std::optional err = this->flush_pending_encrypted_data(); err.has_value()) {
            return err;
        }

        data.remove_prefix(std::get<tls_codec::decrypted_bytes_written>(wr_result).num);
    }

    return std::nullopt;
}

std::optional<socket::error> secured_socket::send_dns_packet(Uint8View data) {
    uint16_t length = htons(data.size());

    uint8_t buffer[sizeof(length) + data.size()];
    memcpy(buffer, (uint8_t *)&length, sizeof(length));
    memcpy(buffer + sizeof(length), data.data(), data.size());

    return this->send({ buffer, sizeof(buffer) });
}

bool secured_socket::set_timeout(std::chrono::microseconds timeout) {
    return this->underlying_socket->set_timeout(timeout);
}

std::optional<socket::error> secured_socket::set_callbacks(struct callbacks cbx) {
    std::scoped_lock l(this->callbacks.mtx);
    this->callbacks.val = cbx;
    return std::nullopt;
}

void secured_socket::on_connected(void *arg) {
    auto *self = (secured_socket *)arg;
    assert(self->state == SS_CONNECTING_SOCKET);

    if (std::optional err = self->codec.connect(self->sni, self->alpn);
            err.has_value()) {
        if (struct callbacks cbx = self->get_callbacks(); cbx.on_close != nullptr) {
            cbx.on_close(cbx.arg, { { -1, std::move(err->description) } });
            return;
        }
    }

    if (std::optional err = self->flush_pending_encrypted_data(); err.has_value()) {
        if (struct callbacks cbx = self->get_callbacks(); cbx.on_close != nullptr) {
            cbx.on_close(cbx.arg, std::move(err));
            return;
        }
    }

    self->state = SS_CONNECTING_TLS;
}

void secured_socket::on_read(void *arg, Uint8View data) {
    auto *self = (secured_socket *)arg;

    if (std::optional err = self->codec.recv_encrypted(data); err.has_value()) {
        if (struct callbacks cbx = self->get_callbacks(); cbx.on_close != nullptr) {
            cbx.on_close(cbx.arg, { { -1, std::move(err->description) } });
        }
    }

    if (std::optional err = self->flush_pending_encrypted_data(); err.has_value()) {
        if (struct callbacks cbx = self->get_callbacks(); cbx.on_close != nullptr) {
            cbx.on_close(cbx.arg, std::move(err));
        }
    }

    if (self->state == SS_CONNECTING_TLS && self->codec.is_connected()) {
        self->state = SS_CONNECTED;
        if (struct callbacks cbx = self->get_callbacks(); cbx.on_connected != nullptr) {
            cbx.on_connected(cbx.arg);
        }
    }

    while (self->codec.want_read_decrypted()) {
        tls_codec::chunk decrypted_chunk;

        {
            std::unique_lock l(self->callbacks.mtx);
            struct callbacks cbx = self->callbacks.val;
            if (cbx.on_read == nullptr) {
                break;
            }

            tls_codec::read_decrypted_result r = self->codec.read_decrypted();
            if (auto *err = std::get_if<tls_codec::error>(&r); err != nullptr) {
                if (cbx.on_close != nullptr) {
                    l.unlock();
                    cbx.on_close(cbx.arg, { { -1, std::move(err->description) } });
                    l.lock();
                    return;
                }
            }

            decrypted_chunk = std::move(std::get<tls_codec::chunk>(r));
        }

        if (struct callbacks cbx = self->get_callbacks(); cbx.on_read != nullptr) {
            if (!decrypted_chunk.data.empty()) {
                // @todo: buffer and re-raise it later if needed
                dbglog(self->log, "{} bytes were dropped", decrypted_chunk.data.size());
            }
            cbx.on_read(cbx.arg, { decrypted_chunk.data.data(), decrypted_chunk.data.size() });
        }
    }
}

void secured_socket::on_close(void *arg, std::optional<error> error) {
    auto *self = (secured_socket *)arg;
    if (struct callbacks cbx = self->get_callbacks(); cbx.on_close != nullptr) {
        cbx.on_close(cbx.arg, std::move(error));
    }
}

socket::connect_parameters secured_socket::make_underlying_connect_parameters(
        connect_parameters &params) const {
    return {
            params.loop,
            params.peer,
            { on_connected, on_read, on_close, (void *)this },
            params.timeout,
    };
}

socket::callbacks secured_socket::get_callbacks() {
    std::scoped_lock l(this->callbacks.mtx);
    return this->callbacks.val;
}

std::optional<socket::error> secured_socket::flush_pending_encrypted_data() {
    while (this->codec.want_send_encrypted()) {
        tls_codec::send_encrypted_result send_result = this->codec.send_encrypted();
        if (auto *err = std::get_if<tls_codec::error>(&send_result); err != nullptr) {
            return { { -1, std::move(err->description) } };
        }

        const auto &chunk = std::get<tls_codec::chunk>(send_result);
        if (auto err = this->underlying_socket->send({ chunk.data.data(), chunk.data.size() });
                err.has_value()) {
            return err;
        }
    }

    return std::nullopt;
}
