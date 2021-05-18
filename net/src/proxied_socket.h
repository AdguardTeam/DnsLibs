#pragma once


#include <ag_socket.h>
#include "outbound_proxy.h"


namespace ag {

class proxied_socket : public socket {
public:
    proxied_socket(outbound_proxy &outbound_proxy, socket_factory::socket_parameters p, prepare_fd_callback prepare_fd);
    ~proxied_socket() override;

    proxied_socket(proxied_socket &&) = delete;
    proxied_socket &operator=(proxied_socket &&) = delete;
    proxied_socket(const proxied_socket &) = delete;
    proxied_socket &operator=(const proxied_socket &) = delete;

private:
    outbound_proxy &proxy;
    with_mtx<callbacks> callbacks = {};
    std::optional<uint32_t> proxy_id;

    [[nodiscard]] std::optional<evutil_socket_t> get_fd() const override;
    [[nodiscard]] std::optional<error> connect(connect_parameters params) override;
    [[nodiscard]] std::optional<error> send(uint8_view data) override;
    [[nodiscard]] std::optional<error> send_dns_packet(uint8_view data) override;
    [[nodiscard]] bool set_timeout(std::chrono::microseconds timeout) override;
    [[nodiscard]] std::optional<error> set_callbacks(struct callbacks cbx) override;

    [[nodiscard]] struct callbacks get_callbacks();

    static void on_connected(void *arg, uint32_t conn_id);
    static void on_read(void *arg, uint8_view data);
    static void on_close(void *arg, std::optional<error> error);

};

}
