#pragma once


#include <optional>
#include <mutex>
#include <ag_defs.h>
#include "outbound_proxy.h"


namespace ag {

class socks_oproxy : public outbound_proxy {
public:
    socks_oproxy(const outbound_proxy_settings *settings, struct parameters parameters);
    ~socks_oproxy() override;

    socks_oproxy(socks_oproxy &&) = delete;
    socks_oproxy &operator=(socks_oproxy &&) = delete;
    socks_oproxy(const socks_oproxy &) = delete;
    socks_oproxy &operator=(const socks_oproxy &) = delete;

private:
    struct connection;
    struct udp_association;
    mutable std::mutex guard;
    hash_map<uint32_t, std::unique_ptr<connection>> connections;
    hash_map<event_loop *, std::unique_ptr<udp_association>> udp_associations;
    hash_map<uint32_t, std::unique_ptr<connection>> closing_connections;

    [[nodiscard]] protocols_set get_supported_protocols() const override;
    [[nodiscard]] std::optional<evutil_socket_t> get_fd(uint32_t conn_id) const override;
    [[nodiscard]] std::optional<socket::error> send(uint32_t conn_id, uint8_view data) override;
    [[nodiscard]] bool set_timeout(uint32_t conn_id, std::chrono::microseconds timeout) override;
    [[nodiscard]] std::optional<socket::error> set_callbacks(uint32_t conn_id, callbacks cbx) override;
    void close_connection(uint32_t conn_id) override;
    [[nodiscard]] std::optional<socket::error> connect_to_proxy(uint32_t conn_id,
            const connect_parameters &parameters) override;
    [[nodiscard]] std::optional<socket::error> connect_through_proxy(uint32_t conn_id,
            const connect_parameters &parameters) override;

    static void on_connected(void *arg);
    static void on_read(void *arg, uint8_view data);
    static void on_close(void *arg, std::optional<socket::error> error);

    [[nodiscard]] std::optional<socket::error> connect_to_proxy(connection *conn);
    void close_connection(connection *conn);
    [[nodiscard]] bool is_udp_association_connection(uint32_t conn_id) const;
    void handle_connection_close(connection *conn, std::optional<socket::error> error);
    void on_udp_association_established(connection *assoc_conn, socket_address bound_addr);
    void terminate_udp_association(connection *assoc_conn);
    void terminate_udp_association_silently(connection *assoc_conn, std::optional<uint32_t> initiated_conn_id);
    callbacks get_connection_callbacks_locked(connection *conn);

    [[nodiscard]] std::optional<socket::error> send_socks4_request(connection *conn);
    void on_socks4_reply(connection *conn, uint8_view data);

    [[nodiscard]] std::optional<socket::error> send_socks5_auth_method_request(connection *conn);
    void on_socks5_auth_method_response(connection *conn, uint8_view data);
    [[nodiscard]] std::optional<socket::error> send_socks5_user_pass_auth_request(connection *conn);
    void on_socks5_user_pass_auth_response(connection *conn, uint8_view data);
    [[nodiscard]] std::optional<socket::error> send_socks5_connect_request(connection *conn);
    void on_socks5_connect_response(connection *conn, uint8_view data);
};

}
