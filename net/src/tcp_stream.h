#pragma once


#include <mutex>
#include <ag_defs.h>
#include <ag_net_utils.h>
#include <ag_socket.h>
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
    std::unique_ptr<bufferevent, ftor<&bufferevent_free>> bev;
    mutable std::mutex guard;
    callbacks callbacks = {};
    std::chrono::microseconds current_timeout{ 0 };

    [[nodiscard]] std::optional<evutil_socket_t> get_fd() const override;
    [[nodiscard]] std::optional<error> connect(connect_parameters params) override;
    [[nodiscard]] std::optional<error> send(uint8_view data) override;
    [[nodiscard]] std::optional<error> send_dns_packet(uint8_view data) override;
    [[nodiscard]] bool set_timeout(std::chrono::microseconds timeout) override;
    [[nodiscard]] std::optional<error> set_callbacks(struct callbacks cbx) override;

    [[nodiscard]] bool set_timeout();
    [[nodiscard]] struct callbacks get_callbacks() const;

    static int on_prepare_fd(int fd, const struct sockaddr *sa, int salen, void *arg);
    static void on_event(bufferevent *bev, short what, void *arg);
    static void on_read(bufferevent *bev, void *arg);
};

}
