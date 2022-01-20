#pragma once


#include "common/defs.h"
#include "common/net_utils.h"
#include "common/logger.h"
#include <ag_socket.h>
#include <ag_deferred_arg.h>
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
    UniquePtr<event, &event_free> socket_event;
    mutable std::mutex guard;
    callbacks callbacks = {};
    std::optional<std::chrono::microseconds> timeout;
    ag::deferred_arg_guard deferred_arg;
    ag::event_loop::task_id connect_notify_task_id;
    ag::event_loop *event_loop = nullptr;

    [[nodiscard]] std::optional<evutil_socket_t> get_fd() const override;
    [[nodiscard]] std::optional<error> connect(connect_parameters params) override;
    [[nodiscard]] std::optional<error> send(Uint8View data) override;
    [[nodiscard]] std::optional<error> send_dns_packet(Uint8View data) override;
    [[nodiscard]] bool set_timeout(std::chrono::microseconds timeout) override;
    [[nodiscard]] std::optional<error> set_callbacks(struct callbacks cbx) override;

    [[nodiscard]] struct callbacks get_callbacks() const;

    static void on_event(evutil_socket_t fd, short what, void *arg);
};

}
