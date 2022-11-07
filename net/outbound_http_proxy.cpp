#include <magic_enum.hpp>

#include "common/base64.h"
#include "common/utils.h"
#include "outbound_http_proxy.h"

#define log_proxy(p_, lvl_, fmt_, ...)                                                                                 \
    lvl_##log((p_)->m_log, "[id={}] {}(): " fmt_, (p_)->m_id, __func__, ##__VA_ARGS__)
#define log_conn(p_, id_, lvl_, fmt_, ...)                                                                             \
    lvl_##log((p_)->m_log, "[id={}/{}] {}(): " fmt_, (p_)->m_id, (id_), __func__, ##__VA_ARGS__)

namespace ag::dns {

enum ConnectionState {
    CS_IDLE,
    CS_CONNECTING_SOCKET,
    CS_CONNECTING_HTTP,
    CS_CONNECTED,
    CS_CLOSING,
};

struct HttpOProxy::Connection {
    HttpOProxy *proxy;
    uint32_t id;
    ConnectParameters parameters = {};
    ConnectionState state = CS_IDLE;
    SocketFactory::SocketPtr socket;
    std::string recv_buffer;
};

HttpOProxy::HttpOProxy(const OutboundProxySettings *settings, Parameters parameters)
        : OutboundProxy(__func__, settings, std::move(parameters)) {
    if (m_settings->protocol == OutboundProxyProtocol::HTTPS_CONNECT) {
        m_tls_session_cache
                = std::make_optional<TlsSessionCache>(AG_FMT("{}:{}", m_settings->address, m_settings->port));
    }
}

OutboundProxy::ProtocolsSet HttpOProxy::get_supported_protocols() const {
    return 1 << utils::TP_TCP;
}

std::optional<evutil_socket_t> HttpOProxy::get_fd(uint32_t conn_id) const {
    std::scoped_lock l(m_guard);
    auto it = m_connections.find(conn_id);
    return (it != m_connections.end()) ? it->second->socket->get_fd() : std::nullopt;
}

Error<SocketError> HttpOProxy::send(uint32_t conn_id, Uint8View data) {
    log_conn(this, conn_id, trace, "{}", data.size());

    std::scoped_lock l(m_guard);
    auto it = m_connections.find(conn_id);
    if (it == m_connections.end()) {
        return make_error(SocketError::AE_CONNECTION_ID_NOT_FOUND, fmt::to_string(conn_id));
    }

    Connection *conn = it->second.get();
    if (auto e = conn->socket->send(data)) {
        log_conn(this, conn_id, dbg, "Failed to send data chunk");
        return e;
    }

    return {};
}

bool HttpOProxy::set_timeout(uint32_t conn_id, Micros timeout) {
    log_conn(this, conn_id, trace, "{}", timeout);

    std::scoped_lock l(m_guard);
    auto it = m_connections.find(conn_id);
    if (it == m_connections.end()) {
        log_conn(this, conn_id, dbg, "Non-existent connection: {}", conn_id);
        return false;
    }

    return it->second->socket->set_timeout(timeout);
}

Error<SocketError> HttpOProxy::set_callbacks_impl(uint32_t conn_id, Callbacks cbx) {
    log_conn(this, conn_id, trace, "...");

    std::scoped_lock l(m_guard);
    auto it = m_connections.find(conn_id);
    if (it == m_connections.end()) {
        return make_error(SocketError::AE_CONNECTION_ID_NOT_FOUND, fmt::to_string(conn_id));
    }

    Connection *conn = it->second.get();
    conn->parameters.callbacks = cbx;
    if (auto e = it->second->socket->set_callbacks({(cbx.on_connected != nullptr) ? on_connected : nullptr,
                (cbx.on_read != nullptr) ? on_read : nullptr, (cbx.on_close != nullptr) ? on_close : nullptr, conn})) {
        return e;
    }

    return {};
}

void HttpOProxy::close_connection_impl(uint32_t conn_id) {
    log_conn(this, conn_id, trace, "...");

    std::scoped_lock l(m_guard);
    auto node = m_connections.extract(conn_id);
    if (node.empty()) {
        log_conn(this, conn_id, dbg, "Connection was not found");
        return;
    }

    Connection *conn = node.mapped().get();
    m_closing_connections.insert(std::move(node));

    if (conn->state == CS_CONNECTING_SOCKET) {
        conn->parameters.callbacks.on_proxy_connection_failed(conn->parameters.callbacks.arg, {});
    }
    conn->parameters.callbacks = {};

    [[maybe_unused]] auto e = conn->socket->set_callbacks({});

    conn->parameters.loop->submit([this, conn_id]() {
        std::scoped_lock l(m_guard);
        m_closing_connections.erase(conn_id);
    });
}

Error<SocketError> HttpOProxy::connect_to_proxy(uint32_t conn_id, const ConnectParameters &parameters) {
    log_conn(this, conn_id, trace, "{} == {}", m_resolved_proxy_address->str(), parameters.peer.str());
    assert(parameters.proto == utils::TP_TCP);

    std::scoped_lock l(m_guard);
    auto &conn = m_connections[conn_id];
    if (conn != nullptr) {
        return make_error(SocketError::AE_DUPLICATE_ID, fmt::to_string(conn_id));
    }

    conn = std::make_unique<Connection>(Connection{this, conn_id, parameters});
    if (m_settings->protocol == OutboundProxyProtocol::HTTPS_CONNECT) {
        conn->socket = m_parameters.make_socket.func(
                m_parameters.make_socket.arg, parameters.proto, {{&m_tls_session_cache.value()}});
    } else {
        conn->socket = m_parameters.make_socket.func(m_parameters.make_socket.arg, parameters.proto, std::nullopt);
    }
    if (auto e = conn->socket->connect({parameters.loop, m_resolved_proxy_address.value(),
                {on_connected, on_read, on_close, conn.get()}, parameters.timeout})) {
        log_conn(this, conn_id, dbg, "Failed to start socket connection");
        m_connections.erase(conn_id);
        return e;
    }

    conn->state = CS_CONNECTING_SOCKET;

    return {};
}

static Uint8View string_to_bytes(std::string_view str) {
    return {(uint8_t *) str.data(), str.size()};
}

Error<SocketError> HttpOProxy::connect_through_proxy(uint32_t conn_id, const ConnectParameters &parameters) {
    log_conn(this, conn_id, trace, "{}:{} == {}", m_settings->address, m_settings->port, parameters.peer.str());

    std::scoped_lock l(m_guard);
    auto &conn = m_connections[conn_id];
    if (conn == nullptr) {
        return make_error(SocketError::AE_CONNECTION_ID_NOT_FOUND, fmt::to_string(conn_id));
    }

    if (conn->state != CS_CONNECTING_SOCKET) {
        log_conn(this, conn_id, dbg, "Invalid connection state: {}", magic_enum::enum_name(conn->state));
        return make_error(SocketError::AE_INVALID_CONN_STATE, AG_FMT("id={} state={}", conn_id, magic_enum::enum_name(conn->state)));
    }

#define SEND_S(conn_, str_)                                                                                            \
    do {                                                                                                               \
        if (auto e = (conn_)->socket->send(string_to_bytes(str_))) {                                                   \
            log_conn(this, conn_id, dbg, "Failed to send connect request");                                            \
            return e;                                                                                                  \
        }                                                                                                              \
    } while (0)

    SEND_S(conn, "CONNECT ");
    SEND_S(conn, parameters.peer.str());
    SEND_S(conn, " HTTP/1.1\r\nHost: ");
    SEND_S(conn, parameters.peer.host_str());
    SEND_S(conn, "\r\n");
    if (m_settings->auth_info.has_value()) {
        std::string auth_key = AG_FMT("{}:{}", m_settings->auth_info->username, m_settings->auth_info->password);
        SEND_S(conn, "Proxy-Authorization: Basic ");
        SEND_S(conn, encode_to_base64(string_to_bytes(auth_key), false));
        SEND_S(conn, "\r\n");
    }
    SEND_S(conn, "\r\n");

#undef SEND_S

    conn->state = CS_CONNECTING_HTTP;

    return {};
}

void HttpOProxy::on_connected(void *arg) {
    auto *conn = (Connection *) arg;
    HttpOProxy *self = conn->proxy;
    log_conn(self, conn->id, trace, "...");

    if (Callbacks cbx = self->get_connection_callbacks_locked(conn); cbx.on_successful_proxy_connection != nullptr) {
        cbx.on_successful_proxy_connection(cbx.arg);
    }

    if (auto e = self->connect_through_proxy(conn->id, conn->parameters)) {
        on_close(conn, std::move(e));
    }
}

void HttpOProxy::on_read(void *arg, Uint8View data) {
    auto *conn = (Connection *) arg;
    HttpOProxy *self = conn->proxy;
    log_conn(self, conn->id, trace, "{}", data.size());

    if (data.empty()) {
        on_close(conn, {});
        return;
    }

    switch (conn->state) {
    case CS_CONNECTING_HTTP:
        self->handle_http_response_chunk(conn, {(char *) data.data(), data.size()});
        break;
    case CS_CONNECTED:
        if (Callbacks cbx = self->get_connection_callbacks_locked(conn); cbx.on_read != nullptr) {
            cbx.on_read(cbx.arg, data);
        } else {
            log_conn(self, conn->id, dbg, "Dropping packet ({} bytes) as read is turned off", data.size());
        }
        break;
    case CS_IDLE:
    case CS_CONNECTING_SOCKET:
    case CS_CLOSING:
    {
        log_conn(self, conn->id, dbg, "Invalid state: {}", magic_enum::enum_name(conn->state));
        auto err = make_error(SocketError::AE_INVALID_CONN_STATE, AG_FMT("id={} state={}", conn->id, magic_enum::enum_name(conn->state)));
        on_close(conn, err);
        break;
    }
    }
}

void HttpOProxy::on_close(void *arg, Error<SocketError> error) {
    auto *conn = (Connection *) arg;
    HttpOProxy *self = conn->proxy;
    if (error) {
        log_conn(self, conn->id, trace, "{}", error->str());
    }

    Callbacks callbacks = self->get_connection_callbacks_locked(conn);
    if (conn->state == CS_CONNECTING_SOCKET && callbacks.on_proxy_connection_failed != nullptr) {
        callbacks.on_proxy_connection_failed(callbacks.arg, error);
    }

    conn->state = CS_CLOSING;

    if (callbacks.on_close != nullptr) {
        callbacks.on_close(callbacks.arg, std::move(error));
    }
}

int HttpOProxy::ssl_verify_callback(X509_STORE_CTX *ctx, void *arg) {
    SSL *ssl = (SSL *) X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
    auto *self = (HttpOProxy *) arg;

    if (self->m_settings->trust_any_certificate) {
        log_proxy(self, trace, "Trusting any proxy certificate as specified in settings");
        return 1;
    }

    if (auto err = self->m_parameters.verifier->verify(ctx, SSL_get_servername(ssl, SSL_get_servername_type(ssl)))) {
        log_proxy(self, dbg, "Failed to verify certificate: {}", *err);
        return 0;
    }

    log_proxy(self, trace, "Verified successfully");

    return 1;
}

void HttpOProxy::handle_http_response_chunk(Connection *conn, std::string_view chunk) {
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
        on_close(conn, make_error(SocketError::AE_BAD_PROXY_REPLY));
        return;
    }

    conn->state = CS_CONNECTED;
    conn->recv_buffer.resize(0);
    if (Callbacks cbx = this->get_connection_callbacks_locked(conn); cbx.on_connected != nullptr) {
        cbx.on_connected(cbx.arg, conn->id);
    }
}

HttpOProxy::Callbacks HttpOProxy::get_connection_callbacks_locked(Connection *conn) {
    std::scoped_lock l(m_guard);
    assert(m_connections.count(conn->id) != 0);
    return conn->parameters.callbacks;
}

} // namespace ag::dns
