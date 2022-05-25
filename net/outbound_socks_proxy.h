#pragma once


#include <optional>
#include <mutex>
#include "common/defs.h"
#include "outbound_proxy.h"


namespace ag {

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
    mutable std::mutex m_guard;
    HashMap<uint32_t, std::unique_ptr<Connection>> m_connections;
    HashMap<EventLoop *, std::unique_ptr<UdpAssociation>> m_udp_associations;
    HashMap<uint32_t, std::unique_ptr<Connection>> m_closing_connections;

    [[nodiscard]] ProtocolsSet get_supported_protocols() const override;
    [[nodiscard]] std::optional<evutil_socket_t> get_fd(uint32_t conn_id) const override;
    [[nodiscard]] std::optional<Socket::Error> send(uint32_t conn_id, Uint8View data) override;
    [[nodiscard]] bool set_timeout(uint32_t conn_id, Micros timeout) override;
    [[nodiscard]] std::optional<Socket::Error> set_callbacks(uint32_t conn_id, Callbacks cbx) override;
    void close_connection(uint32_t conn_id) override;
    [[nodiscard]] std::optional<Socket::Error> connect_to_proxy(uint32_t conn_id,
                                                                const ConnectParameters &parameters) override;
    [[nodiscard]] std::optional<Socket::Error> connect_through_proxy(uint32_t conn_id,
                                                                     const ConnectParameters &parameters) override;

    static void on_connected(void *arg);
    static void on_read(void *arg, Uint8View data);
    static void on_close(void *arg, std::optional<Socket::Error> error);

    [[nodiscard]] std::optional<Socket::Error> connect_to_proxy(Connection *conn);
    void close_connection(Connection *conn);
    [[nodiscard]] bool is_udp_association_connection(uint32_t conn_id) const;
    void handle_connection_close(Connection *conn, std::optional<Socket::Error> error);
    void on_udp_association_established(Connection *assoc_conn, SocketAddress bound_addr);
    void terminate_udp_association(Connection *assoc_conn);
    void terminate_udp_association_silently(Connection *assoc_conn, std::optional<uint32_t> initiated_conn_id);
    Callbacks get_connection_callbacks_locked(Connection *conn);

    [[nodiscard]] std::optional<Socket::Error> send_socks4_request(Connection *conn);
    void on_socks4_reply(Connection *conn, Uint8View data);

    [[nodiscard]] std::optional<Socket::Error> send_socks5_auth_method_request(Connection *conn);
    void on_socks5_auth_method_response(Connection *conn, Uint8View data);
    [[nodiscard]] std::optional<Socket::Error> send_socks5_user_pass_auth_request(Connection *conn);
    void on_socks5_user_pass_auth_response(Connection *conn, Uint8View data);
    [[nodiscard]] std::optional<Socket::Error> send_socks5_connect_request(Connection *conn);
    void on_socks5_connect_response(Connection *conn, Uint8View data);
};

}
