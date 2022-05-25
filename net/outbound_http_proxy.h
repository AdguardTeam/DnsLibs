#pragma once


#include <optional>
#include <mutex>
#include "common/defs.h"
#include "net/tls_session_cache.h"
#include "outbound_proxy.h"


namespace ag {

class HttpOProxy : public OutboundProxy {
public:
    HttpOProxy(const OutboundProxySettings *settings, Parameters parameters);
    ~HttpOProxy() override = default;

    HttpOProxy(HttpOProxy &&) = delete;
    HttpOProxy &operator=(HttpOProxy &&) = delete;
    HttpOProxy(const HttpOProxy &) = delete;
    HttpOProxy &operator=(const HttpOProxy &) = delete;

private:
    struct Connection;
    mutable std::mutex m_guard;
    HashMap<uint32_t, std::unique_ptr<Connection>> m_connections;
    std::optional<TlsSessionCache> m_tls_session_cache;
    HashMap<uint32_t, std::unique_ptr<Connection>> m_closing_connections;

    [[nodiscard]] ProtocolsSet get_supported_protocols() const override;
    [[nodiscard]] std::optional<evutil_socket_t> get_fd(uint32_t conn_id) const override;
    [[nodiscard]] std::optional<Socket::Error> send(uint32_t conn_id, Uint8View data) override;
    [[nodiscard]] bool set_timeout(uint32_t conn_id, Micros timeout) override;
    [[nodiscard]] std::optional<Socket::Error> set_callbacks(uint32_t conn_id, Callbacks cbx) override;
    void close_connection(uint32_t conn_id) override;
    [[nodiscard]] std::optional<Socket::Error> connect_to_proxy(uint32_t conn_id, const ConnectParameters &parameters) override;
    [[nodiscard]] std::optional<Socket::Error> connect_through_proxy(uint32_t conn_id, const ConnectParameters &parameters) override;

    static void on_connected(void *arg);
    static void on_read(void *arg, Uint8View data);
    static void on_close(void *arg, std::optional<Socket::Error> error);
    static int ssl_verify_callback(X509_STORE_CTX *ctx, void *arg);

    void handle_http_response_chunk(Connection *conn, std::string_view chunk);

    Callbacks get_connection_callbacks_locked(Connection *conn);
};

}
