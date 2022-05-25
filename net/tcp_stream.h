#pragma once


#include <chrono>
#include <mutex>
#include <optional>
#include "common/defs.h"
#include "common/net_utils.h"
#include "net/socket.h"
#include "common/deferred_arg.h"
#include <event2/bufferevent.h>


namespace ag {

class TcpStream : public Socket {
public:
    TcpStream(SocketFactory::SocketParameters p, PrepareFdCallback prepare_fd);
    ~TcpStream() override = default;

    TcpStream(TcpStream &&) = delete;
    TcpStream &operator=(TcpStream &&) = delete;
    TcpStream(const TcpStream &) = delete;
    TcpStream &operator=(const TcpStream &) = delete;

private:
    UniquePtr<bufferevent, &bufferevent_free> m_bev;
    UniquePtr<event, &event_free> m_timer;
    mutable std::mutex m_guard;
    Callbacks m_callbacks = {};
    std::optional<Micros> m_current_timeout;
    DeferredArg::Guard m_deferred_arg;

    [[nodiscard]] std::optional<evutil_socket_t> get_fd() const override;
    [[nodiscard]] std::optional<Error> connect(ConnectParameters params) override;
    [[nodiscard]] std::optional<Error> send(Uint8View data) override;
    [[nodiscard]] std::optional<Error> send_dns_packet(Uint8View data) override;
    [[nodiscard]] bool set_timeout(Micros timeout) override;
    [[nodiscard]] std::optional<Error> set_callbacks(Callbacks cbx) override;

    [[nodiscard]] Callbacks get_callbacks() const;
    [[nodiscard]] bool set_timeout();
    void reset_timeout_locked();
    void reset_timeout_nolock();

    static int on_prepare_fd(int fd, const struct sockaddr *sa, int salen, void *arg);
    static void on_event(bufferevent *bev, short what, void *arg);
    static void on_read(bufferevent *bev, void *arg);
    static void on_timeout(evutil_socket_t, short, void *arg);
};

}
