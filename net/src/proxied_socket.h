#pragma once


#include <variant>
#include <ag_socket.h>
#include <ag_clock.h>
#include "outbound_proxy.h"


namespace ag {

class proxied_socket : public socket {
public:
    struct close_connection {};
    struct fallback {
        outbound_proxy *proxy;
    };
    using proxy_connection_failed_result = std::variant<
            close_connection,
            fallback
    >;

    struct callbacks {
        /** Raised after the connection to the proxy server succeeded */
        void (* on_successful_proxy_connection)(void *arg);
        /** Raised after an error on the connection to the proxy server */
        proxy_connection_failed_result (* on_proxy_connection_failed)(void *arg, std::optional<int> err);
        /** User context for the callback */
        void *arg;
    };

    struct parameters {
        outbound_proxy &outbound_proxy;
        socket_factory::socket_parameters socket_parameters;
        prepare_fd_callback prepare_fd = {};
        callbacks callbacks = {};
    };

    explicit proxied_socket(parameters p);
    ~proxied_socket() override;

    proxied_socket(proxied_socket &&) = delete;
    proxied_socket &operator=(proxied_socket &&) = delete;
    proxied_socket(const proxied_socket &) = delete;
    proxied_socket &operator=(const proxied_socket &) = delete;

private:
    struct fallback_info {
        event_loop *loop = nullptr;
        socket_address peer;
        steady_clock::time_point connect_timestamp;
        std::optional<std::chrono::microseconds> timeout;
        outbound_proxy *proxy = nullptr;
    };

    outbound_proxy *proxy = nullptr;
    with_mtx<socket::callbacks> socket_callbacks = {};
    std::optional<uint32_t> proxy_id;
    callbacks proxied_callbacks = {};
    std::unique_ptr<fallback_info> fallback_info;

    [[nodiscard]] std::optional<evutil_socket_t> get_fd() const override;
    [[nodiscard]] std::optional<error> connect(connect_parameters params) override;
    [[nodiscard]] std::optional<error> send(uint8_view data) override;
    [[nodiscard]] std::optional<error> send_dns_packet(uint8_view data) override;
    [[nodiscard]] bool set_timeout(std::chrono::microseconds timeout) override;
    [[nodiscard]] std::optional<error> set_callbacks(socket::callbacks cbx) override;

    [[nodiscard]] socket::callbacks get_callbacks();

    static void on_successful_proxy_connection(void *arg);
    static void on_proxy_connection_failed(void *arg, std::optional<int> err);
    static void on_connected(void *arg, uint32_t conn_id);
    static void on_read(void *arg, uint8_view data);
    static void on_close(void *arg, std::optional<error> error);
};

}
