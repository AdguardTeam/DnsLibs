#pragma once


#include <chrono>
#include <mutex>
#include <optional>
#include <event2/bufferevent.h>

#include "common/defs.h"
#include "common/net_utils.h"
#include "dns/net/socket.h"

namespace ag::dns {

class TcpStream : public Socket {
public:
    TcpStream(SocketFactory::SocketParameters p, PrepareFdCallback prepare_fd);
    ~TcpStream() override;

    TcpStream(TcpStream &&) = delete;
    TcpStream &operator=(TcpStream &&) = delete;
    TcpStream(const TcpStream &) = delete;
    TcpStream &operator=(const TcpStream &) = delete;

private:
    UvPtr<uv_tcp_t> m_tcp;
    UvPtr<uv_timer_t> m_timer;
    Callbacks m_callbacks = {};
    bool m_connected = false;
    std::optional<std::chrono::microseconds> m_current_timeout;
    HashMap<uv_write_t *, Uint8Vector> m_writes;
    HashMap<char *, std::unique_ptr<char[]>> m_reads;

    [[nodiscard]] std::optional<evutil_socket_t> get_fd() const override;
    [[nodiscard]] Error<SocketError> connect(ConnectParameters params) override;
    [[nodiscard]] Error<SocketError> send(Uint8View data) override;
    [[nodiscard]] bool set_timeout(Micros timeout) override;
    [[nodiscard]] Error<SocketError> set_callbacks(Callbacks cbx) override;

    void reset_timeout();
    [[nodiscard]] bool update_timer();
    void update_read_status();

    [[nodiscard]] Callbacks get_callbacks() const;

    static void on_event(uv_connect_t* req, int status);
    static void on_read(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf);
    static void on_timeout(uv_timer_t *handle);
    static void on_write(uv_write_t *req, int status);
    static void allocate_read(uv_handle_t *handle, size_t size, uv_buf_t *buf);
};

}
