#pragma once


#include "common/defs.h"
#include "common/net_utils.h"
#include "common/logger.h"
#include "net/socket.h"
#include "common/deferred_arg.h"
#include <event2/event.h>
#include <optional>
#include <memory>
#include <mutex>


namespace ag {


class UdpSocket : public Socket {
public:
    UdpSocket(SocketFactory::SocketParameters p, PrepareFdCallback prepare_fd);
    ~UdpSocket() override;

    UdpSocket(UdpSocket &&) = delete;
    UdpSocket &operator=(UdpSocket &&) = delete;
    UdpSocket(const UdpSocket &) = delete;
    UdpSocket &operator=(const UdpSocket &) = delete;

private:
    UniquePtr<event, &event_free> m_socket_event;
    mutable std::mutex m_guard;
    Callbacks m_callbacks = {};
    std::optional<Micros> m_timeout;
    DeferredArg::Guard m_deferred_arg;
    EventLoop::TaskId m_connect_notify_task_id;
    EventLoop *m_event_loop = nullptr;

    [[nodiscard]] std::optional<evutil_socket_t> get_fd() const override;
    [[nodiscard]] std::optional<Error> connect(ConnectParameters params) override;
    [[nodiscard]] std::optional<Error> send(Uint8View data) override;
    [[nodiscard]] std::optional<Error> send_dns_packet(Uint8View data) override;
    [[nodiscard]] bool set_timeout(Micros timeout) override;
    [[nodiscard]] std::optional<Error> set_callbacks(Callbacks cbx) override;

    [[nodiscard]] Callbacks get_callbacks() const;

    static void on_event(evutil_socket_t fd, short what, void *arg);
};

}
