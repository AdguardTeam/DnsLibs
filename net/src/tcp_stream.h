#pragma once


#include <chrono>
#include <mutex>
#include <optional>
#include "common/defs.h"
#include "common/net_utils.h"
#include <ag_socket.h>
#include <ag_deferred_arg.h>
#include <event2/bufferevent.h>


namespace ag {

class tcp_stream : public socket {
public:
    tcp_stream(socket_factory::socket_parameters p, prepare_fd_callback prepare_fd);
    ~tcp_stream() override = default;

    tcp_stream(tcp_stream &&) = delete;
    tcp_stream &operator=(tcp_stream &&) = delete;
    tcp_stream(const tcp_stream &) = delete;
    tcp_stream &operator=(const tcp_stream &) = delete;

private:
    UniquePtr<bufferevent, &bufferevent_free> bev;
    UniquePtr<event, &event_free> timer;
    mutable std::mutex guard;
    callbacks callbacks = {};
    std::optional<std::chrono::microseconds> current_timeout;
    ag::deferred_arg_guard deferred_arg;

    [[nodiscard]] std::optional<evutil_socket_t> get_fd() const override;
    [[nodiscard]] std::optional<error> connect(connect_parameters params) override;
    [[nodiscard]] std::optional<error> send(Uint8View data) override;
    [[nodiscard]] std::optional<error> send_dns_packet(Uint8View data) override;
    [[nodiscard]] bool set_timeout(std::chrono::microseconds timeout) override;
    [[nodiscard]] std::optional<error> set_callbacks(struct callbacks cbx) override;

    [[nodiscard]] bool set_timeout();
    void reset_timeout_locked();
    void reset_timeout_nolock();
    [[nodiscard]] struct callbacks get_callbacks() const;

    static int on_prepare_fd(int fd, const struct sockaddr *sa, int salen, void *arg);
    static void on_event(bufferevent *bev, short what, void *arg);
    static void on_read(bufferevent *bev, void *arg);
    static void on_timeout(evutil_socket_t, short, void *arg);
};

}
