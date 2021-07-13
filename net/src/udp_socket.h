#pragma once


#include <ag_defs.h>
#include <ag_net_utils.h>
#include <ag_logger.h>
#include <ag_socket.h>
#include <event2/event.h>
#include <optional>
#include <memory>
#include <mutex>


namespace ag {


class udp_socket : public socket {
public:
    udp_socket(socket_factory::socket_parameters p, prepare_fd_callback prepare_fd);
    ~udp_socket() override;

    udp_socket(udp_socket &&) = delete;
    udp_socket &operator=(udp_socket &&) = delete;
    udp_socket(const udp_socket &) = delete;
    udp_socket &operator=(const udp_socket &) = delete;

private:
    std::unique_ptr<event, ftor<&event_free>> socket_event;
    mutable std::mutex guard;
    callbacks callbacks = {};
    std::optional<std::chrono::microseconds> timeout;

    [[nodiscard]] std::optional<evutil_socket_t> get_fd() const override;
    [[nodiscard]] std::optional<error> connect(connect_parameters params) override;
    [[nodiscard]] std::optional<error> send(uint8_view data) override;
    [[nodiscard]] std::optional<error> send_dns_packet(uint8_view data) override;
    [[nodiscard]] bool set_timeout(std::chrono::microseconds timeout) override;
    [[nodiscard]] std::optional<error> set_callbacks(struct callbacks cbx) override;

    [[nodiscard]] struct callbacks get_callbacks() const;

    static void on_event(evutil_socket_t fd, short what, void *arg);
};

}
