
#include <algorithm>
#include <atomic>
#include <cassert>
#include <csignal>
#include <magic_enum.hpp>
#include <thread>
#include <uv.h>

#include "common/socket_address.h"
#include "dns/common/net_consts.h"

#include "dnsproxy_listener.h"

#define log_listener(l_, lvl_, fmt_, ...)                                                                              \
    lvl_##log((l_)->m_log, "[{} {}] {}(): " fmt_, magic_enum::enum_name((l_)->m_settings.protocol),                    \
            (l_)->m_address.str(), __func__, ##__VA_ARGS__)
#define log_id(l_, lvl_, id_, fmt_, ...) lvl_##log(l_, "[{}] {}(): " fmt_, id_, __func__, ##__VA_ARGS__)

#if defined(__APPLE__)
#include <TargetConditionals.h>
#endif // defined(__APPLE__)
// Set the libuv thread pool size. Must happen before any libuv usage to have effect.
#if TARGET_OS_IPHONE
static const int THREAD_POOL_SIZE_RESULT [[maybe_unused]] = uv_os_setenv("UV_THREADPOOL_SIZE", "8");
#else
static const int THREAD_POOL_SIZE_RESULT [[maybe_unused]] = uv_os_setenv("UV_THREADPOOL_SIZE", "24");
#endif

namespace ag::dns {

// For TCP this could be arbitrarily small, but we would prefer to catch the whole request in one buffer.
static constexpr size_t TCP_RECV_BUF_SIZE = UDP_RECV_BUF_SIZE + 2; // + 2 for payload length

static void udp_alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    buf->base = new char[UDP_RECV_BUF_SIZE];
    buf->len = UDP_RECV_BUF_SIZE;
}

// Abstract base for listeners, does uv initialization/stopping
class ListenerBase : public DnsProxyListener {
protected:
    Logger m_log{"listener"};
    DnsProxy *m_proxy{nullptr};
    EventLoop *m_loop;
    SocketAddress m_address;
    ListenerSettings m_settings;
    std::shared_ptr<bool> m_shutdown_guard;

    // Subclass initializes its handles, callbacks, etc.
    // The loop is initialized, but isn't yet running at this point
    // Return nullopt if the loop should run (success)
    // Close any uv_*_init'ed handles before returning in case of an error!
    virtual ErrString before_run() = 0;

public:
    /**
     * @return std::nullopt if ok, error string otherwise
     */
    ErrString init(const ListenerSettings &settings, DnsProxy *proxy, EventLoop *loop) {
        m_settings = settings;
#ifdef _WIN32
        m_settings.fd = -1; // Unsupported on Windows
#else
        m_settings.fd = dup(m_settings.fd); // Take ownership
#endif

        m_proxy = proxy;
        if (!m_proxy) {
            return "Proxy is not set";
        }
        m_loop = loop;
        if (!m_loop) {
            return "Event loop is not set";
        }

        if (m_settings.fd == -1) {
            m_address = SocketAddress{m_settings.address, m_settings.port};
            if (!m_address.valid()) {
                return AG_FMT("Invalid address: {}", settings.address);
            }
        }

        int err = 0;

        auto err_str = before_run();
        if (err_str.has_value()) {
            return err_str;
        }

        m_shutdown_guard = std::make_shared<bool>(true);

        return std::nullopt;
    }

    ~ListenerBase() override {
        evutil_closesocket(m_settings.fd);
    }

    [[nodiscard]] std::pair<ag::utils::TransportProtocol, SocketAddress> get_listen_address() const override {
        return {m_settings.protocol, m_address};
    }
};

class UdpListener : public ListenerBase {
private:
    UvPtr<uv_udp_t> m_udp;

    auto send_reply(uv_buf_t reply, const sockaddr *addr) {
        struct Awaitable {
            uv_udp_t *m_udp{};
            uv_buf_t m_reply{};
            const sockaddr *m_addr{};
            uv_udp_send_t m_req{};
            std::coroutine_handle<> m_h;
            int m_status = 0;
            bool await_ready() {
                m_req.data = this;
                m_status = uv_udp_send(&m_req, m_udp, &m_reply, 1, m_addr, send_cb);
                return m_status != 0;
            }
            auto await_suspend(std::coroutine_handle<> h) {
                m_h = h;
            }
            static void send_cb(uv_udp_send_t *req, int status) {
                auto *self = (Awaitable *) req->data;
                self->m_status = status;
                self->m_h.resume();
            }
            int await_resume() {
                return m_status;
            }
        };
        return Awaitable{.m_udp = m_udp->raw(), .m_reply = reply, .m_addr = addr};
    }

    coro::Task<void> process_request(uv_buf_t request, const sockaddr *addr) {
        std::unique_ptr<char[]> ptr{request.base};
        DnsMessageInfo info{.proto = utils::TP_UDP, .peername = SocketAddress{addr}};
        std::weak_ptr<bool> guard = m_shutdown_guard;
        Uint8Vector result = co_await m_proxy->handle_message(Uint8View{(uint8_t *)request.base, request.len}, &info);
        if (guard.expired()) {
            co_return;
        }
        uv_buf_t reply = uv_buf_init((char *) result.data(), result.size());
        int err = co_await send_reply(reply, info.peername.c_sockaddr());
        if (guard.expired()) {
            co_return;
        }
        if (err < 0) {
            log_listener(this, dbg, "uv_udp_send failed: {}", uv_strerror(err));
        }
        co_return;
    }

    static void recv_cb(
            uv_udp_t *handle, ssize_t nread,
            const uv_buf_t *buf, const struct sockaddr *addr, unsigned flags) {
        std::unique_ptr<char[]> ptr{buf->base};
        auto *self = (UdpListener *) Uv<uv_udp_t>::parent_from_data(handle->data);
        if (!self) {
            return;
        }

        if (nread < 0) {
            log_listener(self, dbg, "Failed: {}", uv_strerror(nread));
            return;
        }
        if (nread == 0) {
            if (addr != nullptr) {
                log_listener(self, dbg, "Received empty packet");
            }
            return;
        }
        if (flags & UV_UDP_PARTIAL) {
            log_listener(self, dbg, "Failed: truncated");
            return;
        }

        ptr.release();
        coro::run_detached(self->process_request(*buf, addr));
    }

protected:
    ErrString before_run() override {
        int err = 0;

        // Init UDP
        m_udp = Uv<uv_udp_t>::create_with_parent(this);
        if ((err = uv_udp_init(m_loop->handle(), m_udp->raw())) < 0) {
            return AG_FMT("uv_udp_init failed: {}", uv_strerror(err));
        }

        if (m_settings.fd == -1) {
            if ((err = uv_udp_bind(m_udp->raw(), m_address.c_sockaddr(), UV_UDP_REUSEADDR)) < 0) {
                return AG_FMT("uv_udp_bind failed: {}", uv_strerror(err));
            }
        } else {
            if ((err = uv_udp_open(m_udp->raw(), m_settings.fd)) < 0) {
                return AG_FMT("uv_udp_open failed: {}", uv_strerror(err));
            }
            m_settings.fd = -1; // uv_udp_open took ownership
        }

        if ((err = uv_udp_recv_start(m_udp->raw(), udp_alloc_cb, recv_cb)) < 0) {
            return AG_FMT("uv_udp_recv_start failed: {}", uv_strerror(err));
        }

        if (m_address.port() == 0) {
            sockaddr_storage name{};
            int namelen = sizeof(name);
            uv_udp_getsockname(m_udp->raw(), (sockaddr *) &name, &namelen);
            m_address = SocketAddress((sockaddr *) &name);
        }
        log_listener(this, info, "Listening on {} (UDP)", m_address.str());

        return std::nullopt;
    }
};

class TcpDnsPayloadParser {
private:
    enum class State { RD_SIZE, RD_PAYLOAD };
    State m_state;
    uint16_t m_size;
    Uint8Vector m_data;

public:
    TcpDnsPayloadParser()
            : m_state{State::RD_SIZE}
            , m_size{0} {
    }

    // Push more data to this parser
    void push_data(Uint8View data) {
        m_data.insert(m_data.end(), data.begin(), data.end());
    }

    // Initialize `out` to contain the next parsed payload
    // Return true if successful or false if more data is needed (in which case `out` won't be modified)
    bool next_payload(Uint8Vector &out) {
        if (m_state == State::RD_SIZE) {
            if (m_data.size() < 2) {
                return false; // Need more data
            }
            m_size = *(uint16_t *) m_data.data();
            m_size = ntohs(m_size);
            m_state = State::RD_PAYLOAD;
        }
        if (m_state == State::RD_PAYLOAD) {
            if (m_data.size() < (size_t) 2 + m_size) {
                return false; // Need more data
            }
            out = Uint8Vector(m_data.begin() + 2, m_data.begin() + 2 + m_size);
            m_data.erase(m_data.begin(), m_data.begin() + 2 + m_size);
            m_state = State::RD_SIZE;
        }
        return true;
    }
};

class TcpDnsConnection {
public:
    explicit TcpDnsConnection(uint64_t id)
            : m_id{id}
            , m_log(__func__)
    {
        m_tcp = Uv<uv_tcp_t>::create_with_parent(this);
    }

    // Call after *handle() is properly initialized
    void start(uv_loop_t *loop, DnsProxy *proxy, bool persistent, Millis idle_timeout,
            std::function<void(uint64_t)> close_callback) {
        log_id(m_log, trace, m_id, "...");

        assert(proxy);
        assert(idle_timeout.count());

        m_idle_timer = Uv<uv_timer_t>::create_with_parent(this);
        uv_timer_init(loop, m_idle_timer->raw());

        m_proxy = proxy;
        m_persistent = persistent;
        m_idle_timeout = idle_timeout;
        m_close_callback = std::move(close_callback);
        m_shutdown_guard = std::make_shared<bool>(true);
        do_read();
    }

    void close() {
        do_close();
    }

    uint64_t id() {
        return m_id;
    }

    uv_tcp_t *handle() {
        return m_tcp->raw();
    }

private:
    const uint64_t m_id;
    Logger m_log;
    DnsProxy *m_proxy{};
    bool m_persistent{false};
    uint8_t m_incoming_buf[TCP_RECV_BUF_SIZE]{};
    UvPtr<uv_tcp_t> m_tcp;
    UvPtr<uv_timer_t> m_idle_timer;
    Millis m_idle_timeout{0};
    std::function<void(uint64_t)> m_close_callback;
    bool m_closed{false};
    TcpDnsPayloadParser m_parser;
    std::shared_ptr<bool> m_shutdown_guard;

    static void alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
        auto *c = (TcpDnsConnection *) Uv<uv_tcp_t>::parent_from_data(handle->data);
        buf->base = (char *) c->m_incoming_buf;
        buf->len = sizeof(c->m_incoming_buf);
    }

    auto send_reply(uv_buf_t reply) {
        struct Awaitable {
            uv_stream_t *m_handle{};
            uv_buf_t m_reply;
            uint16_t m_reply_size_buf_data{};
            uv_buf_t m_bufs[2]{};
            uv_write_t m_req{};
            std::coroutine_handle<> m_h;
            int m_status = 0;
            bool await_ready() {
                m_reply_size_buf_data = htons(m_reply.len);
                m_bufs[0] = uv_buf_init((char *) &m_reply_size_buf_data, sizeof(m_reply_size_buf_data));
                m_bufs[1] = m_reply;
                m_req.data = this;
                m_status = uv_write(&m_req, m_handle, m_bufs, 2, write_cb);
                return m_status != 0;
            }
            auto await_suspend(std::coroutine_handle<> h) {
                m_h = h;
            }
            static void write_cb(uv_write_t *req, int status) {
                auto *self = (Awaitable *) req->data;
                self->m_status = status;
                self->m_h.resume();
            }
            int await_resume() {
                return m_status;
            }
        };
        return Awaitable{.m_handle = (uv_stream_t *) m_tcp->raw(), .m_reply = reply};
    }

    coro::Task<void> process_request(Uint8Vector &&payload) {
        Uint8Vector packet_data = std::move(payload);
        uv_buf_t request = uv_buf_init((char *) packet_data.data(), packet_data.size());

        sockaddr_storage ss{};
        int namelen = sizeof(ss);
        uv_tcp_getpeername(m_tcp->raw(), (sockaddr *) &ss, &namelen);
        auto *addr = (sockaddr *) &ss;

        DnsMessageInfo info{.proto = ag::utils::TP_TCP, .peername = SocketAddress{addr}};
        std::weak_ptr<bool> guard = m_shutdown_guard;
        auto result = co_await m_proxy->handle_message({(const uint8_t *) request.base, request.len}, &info);
        if (guard.expired()) {
            co_return;
        }
        uv_buf_t reply = uv_buf_init((char *) result.data(), result.size());
        int err = co_await this->send_reply(reply);
        if (guard.expired()) {
            co_return;
        }
        if (err < 0) {
            log_id(m_log, trace, m_id, "send error: {}", uv_strerror(err));
        }
        if (!m_persistent) {
            this->do_close();
        }

        co_return;
    }

    static void read_cb(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
        auto *c = (TcpDnsConnection *) Uv<uv_tcp_t>::parent_from_data(stream->data);
        if (c == nullptr) {
            return;
        }
        log_id(c->m_log, trace, c->m_id, "{}", nread);

        if (nread < 0) {
            c->do_close();
            return;
        }

        assert(buf->base == (char *) c->m_incoming_buf);
        c->m_parser.push_data({c->m_incoming_buf, (size_t) nread});

        Uint8Vector payload;
        while (c->m_parser.next_payload(payload)) {
            uv_timer_again(c->m_idle_timer->raw());

            coro::run_detached(c->process_request(std::move(payload)));

            if (!c->m_persistent) { // Stop after the first request
                uv_read_stop(stream);
                break;
            }
        }
    }

    static void idle_timeout_cb(uv_timer_t *h) {
        auto *c = (TcpDnsConnection *) Uv<uv_timer_t>::parent_from_data(h->data);
        c->do_close();
    }

    void do_read() {
        if (uv_read_start((uv_stream_t *) m_tcp->raw(), alloc_cb, read_cb) < 0) {
            do_close();
            return;
        }
        uv_timer_start(m_idle_timer->raw(), idle_timeout_cb, m_idle_timeout.count(), m_idle_timeout.count());
    }

    void do_close() {
        if (m_closed) {
            return;
        }
        m_closed = true;

        if (m_close_callback) {
            m_close_callback(m_id);
        }
    }
};

class TcpListener : public ListenerBase {
private:
    static constexpr auto BACKLOG = 128;

    UvPtr<uv_tcp_t> m_tcp{};
    uint64_t m_id_counter{0};
    HashMap<uint64_t, std::unique_ptr<TcpDnsConnection>> m_connections;

    static void conn_cb(uv_stream_t *server, int status) {
        auto *self = (TcpListener *) Uv<uv_tcp_t>::parent_from_data(server->data);

        if (status < 0) {
            log_listener(self, dbg, "Connection failed: {}", uv_strerror(status));
            return;
        }

        auto conn = std::make_unique<TcpDnsConnection>(self->m_id_counter++);

        int err = uv_tcp_init(self->m_loop->handle(), conn->handle());
        if (err < 0) {
            log_listener(self, dbg, "uv_tcp_init failed: {}", uv_strerror(err));
            return;
        }

        if ((err = uv_accept(server, (uv_stream_t *) conn->handle())) < 0) {
            log_listener(self, dbg, "uv_accept failed: {}", uv_strerror(err));
            return;
        }

        conn->start(self->m_loop->handle(), self->m_proxy, self->m_settings.persistent, self->m_settings.idle_timeout,
                [self, guard = std::weak_ptr<bool>{self->m_shutdown_guard}](uint64_t id) {
                    if (!guard.expired()) {
                        self->m_connections.erase(id);
                    }
                });
        self->m_connections[conn->id()] = std::move(conn);
    }

protected:
    ErrString before_run() override {
        int err = 0;

        m_tcp = Uv<uv_tcp_t>::create_with_parent(this);
        if ((err = uv_tcp_init(m_loop->handle(), m_tcp->raw())) < 0) {
            return AG_FMT("uv_tcp_init failed: {}", uv_strerror(err));
        }

        if (m_settings.fd == -1) {
            if ((err = uv_tcp_bind(m_tcp->raw(), m_address.c_sockaddr(), 0)) < 0) {
                return AG_FMT("uv_tcp_bind failed: {}", uv_strerror(err));
            }
        } else {
            if ((err = uv_tcp_open(m_tcp->raw(), m_settings.fd)) < 0) {
                return AG_FMT("uv_tcp_open failed: {}", uv_strerror(err));
            }
            m_settings.fd = -1; // uv_tcp_open took ownership
        }

        if ((err = uv_listen((uv_stream_t *) m_tcp->raw(), BACKLOG, conn_cb)) < 0) {
            return AG_FMT("uv_listen failed: {}", uv_strerror(err));
        }

        if (m_address.port() == 0) {
            sockaddr_storage name{};
            int namelen = sizeof(name);
            uv_tcp_getsockname(m_tcp->raw(), (sockaddr *) &name, &namelen);
            m_address = SocketAddress((sockaddr *) &name);
        }
        log_listener(this, info, "Listening on {} (TCP)", m_address.str());

        return std::nullopt;
    }
};

DnsProxyListener::CreateResult DnsProxyListener::create_and_listen(const ListenerSettings &settings, DnsProxy *proxy, EventLoop *loop) {
    if (!proxy) {
        return {nullptr, "proxy is nullptr"};
    }

    std::unique_ptr<ListenerBase> ptr;
    switch (settings.protocol) {
    case ag::utils::TP_UDP:
        ptr = std::make_unique<UdpListener>();
        break;
    case ag::utils::TP_TCP:
        ptr = std::make_unique<TcpListener>();
        break;
    default:
        return {nullptr, AG_FMT("Protocol {} not implemented", magic_enum::enum_name(settings.protocol))};
    }

    auto err = ptr->init(settings, proxy, loop);
    if (err.has_value()) {
        return {nullptr, err};
    }

    return {std::move(ptr), std::nullopt};
}

} // namespace ag::dns
