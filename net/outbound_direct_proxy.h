#pragma once


#include "outbound_proxy.h"


namespace ag::dns {

/**
 * This entity is used if an outbound proxy is not available. In that case all outgoing connection
 * are routed directly to theirs target hosts through this fake proxy object.
 */
class DirectOProxy : public OutboundProxy {
public:
    explicit DirectOProxy(Parameters parameters);
    ~DirectOProxy() override = default;

    DirectOProxy(DirectOProxy &&) = delete;
    DirectOProxy &operator=(DirectOProxy &&) = delete;
    DirectOProxy(const DirectOProxy &) = delete;
    DirectOProxy &operator=(const DirectOProxy &) = delete;

    /**
     * Reset all active connections
     */
    void reset_connections();

private:
    struct Connection {
        DirectOProxy *proxy = nullptr;
        uint32_t id = 0;
        std::unique_ptr<Socket> socket;
        ConnectParameters parameters = {};
    };

    HashMap<uint32_t, Connection> m_connections;

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
};

}
