#include "common/utils.h"
#include "common/base64.h"
#include "outbound_http_proxy.h"
#include <magic_enum.hpp>


#define log_proxy(p_, lvl_, fmt_, ...) lvl_##log((p_)->log, "[id={}] {}(): " fmt_, (p_)->id, __func__, ##__VA_ARGS__)
#define log_conn(p_, id_, lvl_, fmt_, ...) lvl_##log((p_)->log, "[id={}/{}] {}(): " fmt_, (p_)->id, (id_), __func__, ##__VA_ARGS__)


using namespace ag;


enum connection_state {
    CS_IDLE,
    CS_CONNECTING_SOCKET,
    CS_CONNECTING_HTTP,
    CS_CONNECTED,
};

struct http_oproxy::connection {
    http_oproxy *proxy;
    uint32_t id;
    connect_parameters parameters = {};
    connection_state state = CS_IDLE;
    socket_factory::socket_ptr socket;
    std::string recv_buffer;
};


http_oproxy::http_oproxy(const outbound_proxy_settings *settings, struct parameters parameters)
    : outbound_proxy(__func__, settings, std::move(parameters))
{
    if (this->settings->protocol == outbound_proxy_protocol::HTTPS_CONNECT) {
        this->tls_session_cache = std::make_optional<ag::tls_session_cache>(
                AG_FMT("{}:{}", this->settings->address, this->settings->port));
    }
}

outbound_proxy::protocols_set http_oproxy::get_supported_protocols() const {
    return 1 << utils::TP_TCP;
}

std::optional<evutil_socket_t> http_oproxy::get_fd(uint32_t conn_id) const {
    std::scoped_lock l(this->guard);
    auto it = this->connections.find(conn_id);
    return (it != this->connections.end()) ? it->second->socket->get_fd() : std::nullopt;
}

std::optional<socket::error> http_oproxy::send(uint32_t conn_id, Uint8View data) {
    log_conn(this, conn_id, trace, "{}", data.size());

    std::scoped_lock l(this->guard);
    auto it = this->connections.find(conn_id);
    if (it == this->connections.end()) {
        return { { -1, AG_FMT("Non-existent connection: {}", conn_id) } };
    }

    connection *conn = it->second.get();
    if (auto e = conn->socket->send(data); e.has_value()) {
        log_conn(this, conn_id, dbg, "Failed to send data chunk");
        return e;
    }

    return std::nullopt;
}

bool http_oproxy::set_timeout(uint32_t conn_id, std::chrono::microseconds timeout) {
    log_conn(this, conn_id, trace, "{}", timeout);

    std::scoped_lock l(this->guard);
    auto it = this->connections.find(conn_id);
    if (it == this->connections.end()) {
        log_conn(this, conn_id, dbg, "Non-existent connection: {}", conn_id);
        return false;
    }

    return it->second->socket->set_timeout(timeout);
}

std::optional<socket::error> http_oproxy::set_callbacks(uint32_t conn_id, callbacks cbx) {
    log_conn(this, conn_id, trace, "...");

    std::scoped_lock l(this->guard);
    auto it = this->connections.find(conn_id);
    if (it == this->connections.end()) {
        return { { -1, AG_FMT("Non-existent connection: {}", conn_id) } };
    }

    connection *conn = it->second.get();
    conn->parameters.callbacks = cbx;
    if (auto e = it->second->socket->set_callbacks({
                (cbx.on_connected != nullptr) ? on_connected : nullptr,
                (cbx.on_read != nullptr) ? on_read : nullptr,
                (cbx.on_close != nullptr) ? on_close : nullptr,
                conn });
            e.has_value()) {
        return e;
    }

    return std::nullopt;
}

void http_oproxy::close_connection(uint32_t conn_id) {
    log_conn(this, conn_id, trace, "...");

    std::scoped_lock l(this->guard);
    auto node = this->connections.extract(conn_id);
    if (node.empty()) {
        log_conn(this, conn_id, dbg, "Connection was not found");
        return;
    }

    connection *conn = node.mapped().get();
    this->closing_connections.insert(std::move(node));

    if (conn->state == CS_CONNECTING_SOCKET) {
        conn->parameters.callbacks.on_proxy_connection_failed(conn->parameters.callbacks.arg, std::nullopt);
    }
    conn->parameters.callbacks = {};

    [[maybe_unused]] auto e = conn->socket->set_callbacks({});

    conn->parameters.loop->submit(
            [this, conn_id] () {
                std::scoped_lock l(this->guard);
                this->closing_connections.erase(conn_id);
            });
}

std::optional<socket::error> http_oproxy::connect_to_proxy(uint32_t conn_id, const connect_parameters &parameters) {
    log_conn(this, conn_id, trace, "{}:{} == {}",
            this->settings->address, this->settings->port, parameters.peer.str());
    assert(parameters.proto == utils::TP_TCP);

    std::scoped_lock l(this->guard);
    auto &conn = this->connections[conn_id];
    if (conn != nullptr) {
        return { { -1, AG_FMT("Duplicate ID: {}", conn_id) } };
    }

    conn = std::make_unique<connection>(connection{ this, conn_id, parameters });
    if (this->settings->protocol == outbound_proxy_protocol::HTTPS_CONNECT) {
        conn->socket = this->parameters.make_socket.func(this->parameters.make_socket.arg,
                parameters.proto, { { &this->tls_session_cache.value() } });
    } else {
        conn->socket = this->parameters.make_socket.func(this->parameters.make_socket.arg,
                parameters.proto, std::nullopt);
    }
    if (auto e = conn->socket->connect({ parameters.loop,
                SocketAddress(this->settings->address, this->settings->port),
                { on_connected, on_read, on_close, conn.get() },
                parameters.timeout });
            e.has_value()) {
        log_conn(this, conn_id, dbg, "Failed to start socket connection");
        this->connections.erase(conn_id);
        return e;
    }

    conn->state = CS_CONNECTING_SOCKET;

    return std::nullopt;
}

static Uint8View string_to_bytes(std::string_view str) {
    return { (uint8_t *)str.data(), str.size() };
}

std::optional<socket::error> http_oproxy::connect_through_proxy(uint32_t conn_id, const connect_parameters &parameters) {
    log_conn(this, conn_id, trace, "{}:{} == {}",
            this->settings->address, this->settings->port, parameters.peer.str());

    std::scoped_lock l(this->guard);
    auto &conn = this->connections[conn_id];
    if (conn == nullptr) {
        return { { -1, AG_FMT("Non-existent connection: {}", conn_id) } };
    }

    if (conn->state != CS_CONNECTING_SOCKET) {
        log_conn(this, conn_id, dbg, "Invalid connection state: {}", magic_enum::enum_name(conn->state));
        return { { -1, "Invalid connection state" } };
    }

#define SEND_S(conn_, str_) \
    do { \
        if (auto e = (conn_)->socket->send(string_to_bytes(str_)); e.has_value()) { \
            log_conn(this, conn_id, dbg, "Failed to send connect request"); \
            return e; \
        } \
    } while (0)

    SEND_S(conn, "CONNECT ");
    SEND_S(conn, parameters.peer.str());
    SEND_S(conn, " HTTP/1.1\r\nHost: ");
    SEND_S(conn, parameters.peer.host_str());
    SEND_S(conn, "\r\n");
    if (this->settings->auth_info.has_value()) {
        std::string auth_key =
                AG_FMT("{}:{}", this->settings->auth_info->username, this->settings->auth_info->password);
        SEND_S(conn, "Proxy-Authorization: Basic ");
        SEND_S(conn, encode_to_base64(string_to_bytes(auth_key), false));
        SEND_S(conn, "\r\n");
    }
    SEND_S(conn, "\r\n");

#undef SEND_S

    conn->state = CS_CONNECTING_HTTP;

    return std::nullopt;
}

void http_oproxy::on_connected(void *arg) {
    auto *conn = (connection *)arg;
    http_oproxy *self = conn->proxy;
    log_conn(self, conn->id, trace, "...");

    if (callbacks cbx = self->get_connection_callbacks_locked(conn);
            cbx.on_successful_proxy_connection != nullptr) {
        cbx.on_successful_proxy_connection(cbx.arg);
    }

    if (auto e = self->connect_through_proxy(conn->id, conn->parameters);
            e.has_value()) {
        on_close(conn, std::move(e));
    }
}

void http_oproxy::on_read(void *arg, Uint8View data) {
    auto *conn = (connection *)arg;
    http_oproxy *self = conn->proxy;
    log_conn(self, conn->id, trace, "{}", data.size());

    if (data.empty()) {
        on_close(conn, std::nullopt);
        return;
    }

    switch (conn->state) {
    case CS_CONNECTING_HTTP:
        self->handle_http_response_chunk(conn, { (char *) data.data(), data.size() });
        break;
    case CS_CONNECTED:
        if (callbacks cbx = self->get_connection_callbacks_locked(conn);
                cbx.on_read != nullptr) {
            cbx.on_read(cbx.arg, data);
        } else {
            log_conn(self, conn->id, dbg, "Dropping packet ({} bytes) as read is turned off", data.size());
        }
        break;
    case CS_IDLE:
    case CS_CONNECTING_SOCKET: {
        log_conn(self, conn->id, dbg, "Invalid state: {}", magic_enum::enum_name(conn->state));
        on_close(conn, { { -1, "Invalid state on reading" } });
        break;
    }
    }
}

void http_oproxy::on_close(void *arg, std::optional<socket::error> error) {
    auto *conn = (connection *)arg;
    http_oproxy *self = conn->proxy;
    if (error.has_value()) {
        log_conn(self, conn->id, trace, "{} ({})", error->description, error->code);
    }

    callbacks callbacks = self->get_connection_callbacks_locked(conn);
    if (conn->state == CS_CONNECTING_SOCKET) {
        callbacks.on_proxy_connection_failed(callbacks.arg,
                error.has_value() ? std::make_optional(error->code) : std::nullopt);
    }

    if (callbacks.on_close != nullptr) {
        callbacks.on_close(callbacks.arg, std::move(error));
    }
}

int http_oproxy::ssl_verify_callback(X509_STORE_CTX *ctx, void *arg) {
    SSL *ssl = (SSL *)X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
    auto *self = (http_oproxy *)arg;

    if (self->settings->trust_any_certificate) {
        log_proxy(self, trace, "Trusting any proxy certificate as specified in settings");
        return 1;
    }

    if (ErrString err = self->parameters.verifier->verify(ctx,
                                                          SSL_get_servername(ssl, SSL_get_servername_type(ssl)));
            err.has_value()) {
        log_proxy(self, dbg, "Failed to verify certificate: {}", err.value());
        return 0;
    }

    log_proxy(self, trace, "Verified successfully");

    return 1;
}

void http_oproxy::handle_http_response_chunk(connection *conn, std::string_view chunk) {
    std::string_view seek;

    if (conn->recv_buffer.empty() && utils::ends_with(chunk, "\r\n\r\n")) {
        seek = chunk;
    } else {
        conn->recv_buffer.append(chunk);
        if (!utils::ends_with(conn->recv_buffer, "\r\n\r\n")) {
            return;
        }

        seek = conn->recv_buffer;
    }

    log_conn(this, conn->id, dbg, "{}", seek);

    if (!utils::starts_with(seek, "HTTP/1.1 200 Connection established\r\n")
            && !utils::starts_with(seek, "HTTP/1.1 200 OK\r\n")) {
        on_close(conn, { { -1, "Bad response" } });
        return;
    }

    conn->state = CS_CONNECTED;
    conn->recv_buffer.resize(0);
    if (callbacks cbx = this->get_connection_callbacks_locked(conn);
            cbx.on_connected != nullptr) {
        cbx.on_connected(cbx.arg, conn->id);
    }
}

http_oproxy::callbacks http_oproxy::get_connection_callbacks_locked(connection *conn) {
    std::scoped_lock l(this->guard);
    assert(this->connections.count(conn->id) != 0);
    return conn->parameters.callbacks;
}
