#pragma once


#include <memory>
#include <optional>

#include "common/defs.h"
#include "outbound_proxy.h"


namespace ag::dns {

class SocksOProxy : public OutboundProxy {
public:
    SocksOProxy(const OutboundProxySettings *settings, Parameters parameters);
    ~SocksOProxy() override;

    SocksOProxy(SocksOProxy &&) = delete;
    SocksOProxy &operator=(SocksOProxy &&) = delete;
    SocksOProxy(const SocksOProxy &) = delete;
    SocksOProxy &operator=(const SocksOProxy &) = delete;

private:
    struct Connection;
    struct UdpAssociation;
    HashMap<uint32_t, std::unique_ptr<Connection>> m_connections;
    std::unique_ptr<UdpAssociation> m_udp_association;

    void deinit_impl() override;
    [[nodiscard]] ProtocolsSet get_supported_protocols() const override;
    [[nodiscard]] std::optional<evutil_socket_t> get_fd(uint32_t conn_id) const override;
    [[nodiscard]] Error<SocketError> send(uint32_t conn_id, Uint8View data) override;
    [[nodiscard]] bool set_timeout(uint32_t conn_id, Micros timeout) override;
    [[nodiscard]] Error<SocketError> set_callbacks_impl(uint32_t conn_id, Callbacks cbx) override;
    void close_connection_impl(uint32_t conn_id) override;
    [[nodiscard]] Error<SocketError> connect_to_proxy(uint32_t conn_id,
                                                                const ConnectParameters &parameters) override;
    [[nodiscard]] Error<SocketError> connect_through_proxy(uint32_t conn_id,
                                                                     const ConnectParameters &parameters) override;

    static void on_connected(void *arg);
    static void on_read(void *arg, Uint8View data);
    static void on_close(void *arg, Error<SocketError> error);

    [[nodiscard]] Error<SocketError> connect_to_proxy(Connection *conn);
    void close_connection(Connection *conn);
    [[nodiscard]] bool is_udp_association_connection(uint32_t conn_id) const;
    void handle_connection_close(Connection *conn, Error<SocketError> error);
    void on_udp_association_established(Connection *assoc_conn, SocketAddress bound_addr);
    void terminate_udp_association(Connection *assoc_conn, Error<SocketError> error);
    void terminate_udp_association_silently(Connection *assoc_conn, std::optional<uint32_t> initiated_conn_id);
    std::optional<Callbacks> get_connection_callbacks_locked(Connection *conn);

    [[nodiscard]] Error<SocketError> send_socks4_request(Connection *conn);
    void on_socks4_reply(Connection *conn, Uint8View data);

    [[nodiscard]] Error<SocketError> send_socks5_auth_method_request(Connection *conn);
    void on_socks5_auth_method_response(Connection *conn, Uint8View data);
    [[nodiscard]] Error<SocketError> send_socks5_user_pass_auth_request(Connection *conn);
    void on_socks5_user_pass_auth_response(Connection *conn, Uint8View data);
    [[nodiscard]] Error<SocketError> send_socks5_connect_request(Connection *conn);
    void on_socks5_connect_response(Connection *conn, Uint8View data);
};

}
