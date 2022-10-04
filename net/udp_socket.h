#pragma once


#include "common/defs.h"
#include "common/net_utils.h"
#include "common/logger.h"
#include "dns/net/socket.h"
#include <event2/event.h>
#include <optional>
#include <memory>
#include <mutex>


namespace ag::dns {


class UdpSocket : public Socket {
public:
    UdpSocket(SocketFactory::SocketParameters p, PrepareFdCallback prepare_fd);
    ~UdpSocket() override;

    UdpSocket(UdpSocket &&) = delete;
    UdpSocket &operator=(UdpSocket &&) = delete;
    UdpSocket(const UdpSocket &) = delete;
    UdpSocket &operator=(const UdpSocket &) = delete;

private:
    UvPtr<uv_udp_t> m_udp;
    UvPtr<uv_timer_t> m_timer;
    Callbacks m_callbacks = {};
    bool m_connected = false;
    std::optional<std::chrono::microseconds> m_current_timeout;
    HashMap<char *, std::unique_ptr<char[]>> m_reads;

    [[nodiscard]] std::optional<evutil_socket_t> get_fd() const override;
    [[nodiscard]] Error<SocketError> connect(ConnectParameters params) override;
    [[nodiscard]] Error<SocketError> send(Uint8View data) override;
    [[nodiscard]] bool set_timeout(Micros timeout) override;
    [[nodiscard]] Error<SocketError> set_callbacks(Callbacks cbx) override;

    [[nodiscard]] Callbacks get_callbacks() const;

    void reset_timeout();
    [[nodiscard]] bool update_timer();
    void update_read_status();

    static void on_timeout(uv_timer_t *handle);
    static void on_read(uv_udp_t *udp, ssize_t nread, const uv_buf_t *buf, const sockaddr * /* addr */, uint32_t /* flags */);
    static void allocate_read(uv_handle_t *handle, size_t size, uv_buf_t *buf);
};

}
