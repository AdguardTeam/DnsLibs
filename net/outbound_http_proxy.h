#pragma once


#include <optional>

#include "common/defs.h"
#include "dns/net/tls_session_cache.h"
#include "outbound_proxy.h"


namespace ag::dns {

class HttpOProxy : public OutboundProxy {
public:
    HttpOProxy(const OutboundProxySettings *settings, Parameters parameters);
    ~HttpOProxy() override;

    HttpOProxy(HttpOProxy &&) = delete;
    HttpOProxy &operator=(HttpOProxy &&) = delete;
    HttpOProxy(const HttpOProxy &) = delete;
    HttpOProxy &operator=(const HttpOProxy &) = delete;

private:
    struct Connection;
    HashMap<uint32_t, std::unique_ptr<Connection>> m_connections;
    std::optional<TlsSessionCache> m_tls_session_cache;

    void deinit_impl() override;
    [[nodiscard]] ProtocolsSet get_supported_protocols() const override;
    [[nodiscard]] std::optional<evutil_socket_t> get_fd(uint32_t conn_id) const override;
    [[nodiscard]] Error<SocketError> send(uint32_t conn_id, Uint8View data) override;
    [[nodiscard]] bool set_timeout(uint32_t conn_id, Micros timeout) override;
    [[nodiscard]] Error<SocketError> set_callbacks_impl(uint32_t conn_id, Callbacks cbx) override;
    void close_connection_impl(uint32_t conn_id) override;
    [[nodiscard]] Error<SocketError> connect_to_proxy(uint32_t conn_id, const ConnectParameters &parameters) override;
    [[nodiscard]] Error<SocketError> connect_through_proxy(uint32_t conn_id, const ConnectParameters &parameters) override;

    static void on_connected(void *arg);
    static void on_read(void *arg, Uint8View data);
    static void on_close(void *arg, Error<SocketError> error);

    void handle_http_response_chunk(Connection *conn, std::string_view chunk);

    Callbacks get_connection_callbacks_locked(Connection *conn);
};

}
