
#include <algorithm>
#include <atomic>
#include <cassert>
#include <csignal>
#include <magic_enum.hpp>
#include <thread>
#include <uv.h>

#include "common/net_consts.h"
#include "common/socket_address.h"

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

namespace ag {

// For TCP this could be arbitrarily small, but we would prefer to catch the whole request in one buffer.
static constexpr size_t TCP_RECV_BUF_SIZE = UDP_RECV_BUF_SIZE + 2; // + 2 for payload length

static void udp_alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    buf->base = new char[UDP_RECV_BUF_SIZE];
    buf->len = UDP_RECV_BUF_SIZE;
}

static void dealloc_buf(const uv_buf_t *buf) {
    delete[] buf->base;
}

// Abstract base for listeners, does uv initialization/stopping
class ListenerBase : public DnsProxyListener {
protected:
    Logger m_log{"listener"};
    DnsProxy *m_proxy{nullptr};
    std::thread m_loop_thread;
    using uv_loop_ptr = UniquePtr<uv_loop_t, &uv_loop_delete>;
    uv_loop_ptr m_loop;
    uv_async_t m_escape_hatch{};
    SocketAddress m_address;
    ListenerSettings m_settings;

    // Subclass initializes its handles, callbacks, etc.
    // The loop is initialized, but isn't yet running at this point
    // Return nullopt if the loop should run (success)
    // Close any uv_*_init'ed handles before returning in case of an error!
    virtual ErrString before_run() = 0;

    // Subclass cleans up to allow the event loop to exit
    // (close handles, cancel pending work, etc.)
    // Called on event loop's thread
    virtual void before_stop() = 0;

private:
    static void escape_hatch_cb(uv_async_t *handle) {
        auto *self = (ListenerBase *) handle->data;
        log_listener(self, dbg, "Received signal to stop");
        self->before_stop();
        uv_close((uv_handle_t *) &self->m_escape_hatch, nullptr);
    }

    static int run_loop(uv_loop_t *loop, uv_run_mode mode) {
#ifdef __MACH__
        static auto ensure_sigpipe_ignored [[maybe_unused]] = signal(SIGPIPE, SIG_IGN);

#elif defined EVTHREAD_USE_PTHREADS_IMPLEMENTED
        // Block SIGPIPE
        sigset_t sigset, oldset;
        sigemptyset(&sigset);
        sigaddset(&sigset, SIGPIPE);
        pthread_sigmask(SIG_BLOCK, &sigset, &oldset);
#endif // __MACH__

        auto err = uv_run(loop, mode);

#if defined(EVTHREAD_USE_PTHREADS_IMPLEMENTED) && !defined(__MACH__)
        // Restore SIGPIPE state
        pthread_sigmask(SIG_SETMASK, &oldset, nullptr);
#endif
        return err;
    }

public:
    /**
     * @return std::nullopt if ok, error string otherwise
     */
    ErrString init(const ListenerSettings &settings, DnsProxy *proxy) {
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

        if (m_settings.fd == -1) {
            m_address = SocketAddress{m_settings.address, m_settings.port};
            if (!m_address.valid()) {
                return AG_FMT("Invalid address: {}", settings.address);
            }
        }

        int err = 0;
        // Init the loop
        if (m_loop = uv_loop_ptr(uv_loop_new()); m_loop == nullptr) {
            return "Failed to create uv loop";
        }

        // Init the escape hatch
        if ((err = uv_async_init(m_loop.get(), &m_escape_hatch, escape_hatch_cb))) {
            return AG_FMT("uv_async_init failed: {}", uv_strerror(err));
        }
        m_escape_hatch.data = this;

        auto err_str = before_run();
        if (err_str.has_value()) {
            uv_close((uv_handle_t *) &m_escape_hatch, nullptr);

            // Run the loop once to let libuv close the handles cleanly
            err = run_loop(m_loop.get(), UV_RUN_DEFAULT);
            assert(0 == err);

            return err_str;
        }

        m_loop_thread = std::thread([this]() {
            int ret = run_loop(m_loop.get(), UV_RUN_DEFAULT);
            if (ret != 0) {
                log_listener(this, err, "uv_run: (%d) %s", ret, uv_strerror(ret));
            } else {
                log_listener(this, info, "Finished listening");
            }
        });

        return std::nullopt;
    }

    ~ListenerBase() override {
        await_shutdown();
        evutil_closesocket(m_settings.fd);
    }

    void shutdown() final {
        // The next invocation of escape_hatch_cb will close all handles, allowing the loop to exit
        if (this == m_escape_hatch.data) { // Check async initialized
            int ret = uv_async_send(&m_escape_hatch);
            if (ret != 0) {
                log_listener(this, err, "uv_async_send: (%d) %s", ret, uv_strerror(ret));
            }
        }
    }

    void await_shutdown() final {
        if (m_loop_thread.joinable()) { // Allow await_shutdown() to be called more than once
            m_loop_thread.join();
        }
    }

    [[nodiscard]] std::pair<ag::utils::TransportProtocol, SocketAddress> get_listen_address() const override {
        return {m_settings.protocol, m_address};
    }
};

class UdpListener : public ListenerBase {
private:
    struct Task {
        uv_work_t work_req{};
        UdpListener *self;
        SocketAddress peer;
        uv_buf_t request;
        Uint8Vector response; // Filled in work_cb

        // Takes ownership of request buffer
        Task(UdpListener *self, const sockaddr *addr, uv_buf_t request)
                : self(self)
                , peer(addr)
                , request(request) {

            work_req.data = this;
        }

        ~Task() {
            dealloc_buf(&request);
        }
    };

    uv_udp_t m_udp_handle{};
    HashSet<Task *> m_pending; // Messages not yet processed by the proxy

    static void work_cb(uv_work_t *req) {
        auto *m = (Task *) req->data;
        DnsMessageInfo info{.proto = ag::utils::TP_UDP, .peername = m->peer};
        m->response = m->self->m_proxy->handle_message({(uint8_t *) m->request.base, m->request.len}, &info);
    }

    static void send_cb(uv_udp_send_t *req, int status) {
        auto *m = (Task *) req->data;
        if (status != 0) {
            log_listener(m->self, dbg, "Error: {}", uv_strerror(status));
        }
        delete req;
        delete m;
    }

    static void after_work_cb(uv_work_t *req, int status) {
        auto *m = (Task *) req->data;

        m->self->m_pending.erase(m);

        if (status == UV_ECANCELED || m->response.empty()) {
            log_listener(m->self, dbg, "{}", status == UV_ECANCELED ? "Task cancelled" : "Response is empty");
            delete m;
            return;
        }

        auto resp_buf = uv_buf_init((char *) m->response.data(), m->response.size());

        auto *send_req = new uv_udp_send_t;
        send_req->data = m;

        const int err = uv_udp_send(send_req, &m->self->m_udp_handle, &resp_buf, 1, m->peer.c_sockaddr(), send_cb);
        if (err < 0) {
            log_listener(m->self, dbg, "uv_udp_send failed: {}", uv_strerror(err));
            delete send_req;
            delete m;
        }
    }

    static void recv_cb(
            uv_udp_t *handle, ssize_t nread, const uv_buf_t *buf, const struct sockaddr *addr, unsigned flags) {
        auto *self = (UdpListener *) handle->data;

        if (nread < 0) {
            log_listener(self, dbg, "Failed: {}", uv_strerror(nread));
            dealloc_buf(buf);
            return;
        }
        if (nread == 0) {
            log_listener(self, dbg, "Received empty packet");
            dealloc_buf(buf);
            return;
        }
        if (flags & UV_UDP_PARTIAL) {
            log_listener(self, dbg, "Failed: truncated");
            dealloc_buf(buf);
            return;
        }

        auto *m = new Task(self, addr, *buf);
        uv_queue_work(self->m_loop.get(), &m->work_req, work_cb, after_work_cb);
        self->m_pending.insert(m);
    }

protected:
    ErrString before_run() override {
        int err = 0;

        // Init UDP
        if ((err = uv_udp_init(m_loop.get(), &m_udp_handle)) < 0) {
            return AG_FMT("uv_udp_init failed: {}", uv_strerror(err));
        }
        m_udp_handle.data = this;

        if (m_settings.fd == -1) {
            if ((err = uv_udp_bind(&m_udp_handle, m_address.c_sockaddr(), UV_UDP_REUSEADDR)) < 0) {
                uv_close((uv_handle_t *) &m_udp_handle, nullptr);
                return AG_FMT("uv_udp_bind failed: {}", uv_strerror(err));
            }
        } else {
            if ((err = uv_udp_open(&m_udp_handle, m_settings.fd)) < 0) {
                uv_close((uv_handle_t *) &m_udp_handle, nullptr);
                return AG_FMT("uv_udp_open failed: {}", uv_strerror(err));
            }
            m_settings.fd = -1; // uv_udp_open took ownership
        }

        if ((err = uv_udp_recv_start(&m_udp_handle, udp_alloc_cb, recv_cb)) < 0) {
            uv_close((uv_handle_t *) &m_udp_handle, nullptr);
            return AG_FMT("uv_udp_recv_start failed: {}", uv_strerror(err));
        }

        if (m_address.port() == 0) {
            sockaddr_storage name{};
            int namelen = sizeof(name);
            uv_udp_getsockname(&m_udp_handle, (sockaddr *) &name, &namelen);
            m_address = SocketAddress((sockaddr *) &name);
        }
        log_listener(this, info, "Listening on {} (UDP)", m_address.str());

        return std::nullopt;
    }

    void before_stop() override {
        uv_close((uv_handle_t *) &m_udp_handle, nullptr);
        log_listener(this, dbg, "Stopping with {} pending tasks", m_pending.size());
        for (auto *m : m_pending) {
            uv_cancel((uv_req_t *) &m->work_req);
        }
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
            , m_tcp((uv_tcp_t *) malloc(sizeof(uv_tcp_t))) // Deleted in close_cb
            , m_idle_timer((uv_timer_t *) malloc(sizeof(uv_timer_t))) // Deleted in close_cb
    {
        m_tcp->data = this;
        m_idle_timer->data = this;
    }

    // Call after *handle() is properly initialized
    void start(uv_loop_t *loop, DnsProxy *proxy, bool persistent, Millis idle_timeout,
            std::function<void(uint64_t)> close_callback) {
        log_id(m_log, trace, m_id, "...");

        assert(proxy);
        assert(idle_timeout.count());

        uv_timer_init(loop, m_idle_timer);

        m_proxy = proxy;
        m_persistent = persistent;
        m_idle_timeout = idle_timeout;
        m_close_callback = std::move(close_callback);
        do_read();
    }

    void close() {
        do_close();
    }

    uint64_t id() {
        return m_id;
    }

    uv_tcp_t *handle() {
        return m_tcp;
    }

private:
    struct Work {
        uv_work_t req{};
        TcpDnsConnection *connection;
        Uint8Vector payload;
        std::atomic_bool cancelled;

        Work(TcpDnsConnection *c, Uint8Vector &&payload)
                : connection{c}
                , payload{std::move(payload)}
                , cancelled{false} {
            this->req.data = this;
        }
    };

    struct Write {
        uv_write_t req{};
        Uint8Vector payload;
        uint16_t size_be; // Big-endian size
        uv_buf_t bufs[2]{};

        explicit Write(Uint8Vector &&payload)
                : payload(std::move(payload)) {
            this->req.data = this;
            this->size_be = htons(this->payload.size());
            bufs[0] = uv_buf_init((char *) &this->size_be, sizeof(this->size_be));
            bufs[1] = uv_buf_init((char *) this->payload.data(), this->payload.size());
        }
    };

    const uint64_t m_id;
    Logger m_log;
    DnsProxy *m_proxy{};
    bool m_persistent{false};
    uint8_t m_incoming_buf[TCP_RECV_BUF_SIZE]{};
    uv_tcp_t *m_tcp{};
    uv_timer_t *m_idle_timer{};
    Millis m_idle_timeout{0};
    std::function<void(uint64_t)> m_close_callback;
    bool m_closed{false};
    TcpDnsPayloadParser m_parser;
    HashSet<Work *> m_pending_works;

    static void alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
        auto *c = (TcpDnsConnection *) handle->data;
        buf->base = (char *) c->m_incoming_buf;
        buf->len = sizeof(c->m_incoming_buf);
    }

    static void read_cb(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
        auto *c = (TcpDnsConnection *) stream->data;
        log_id(c->m_log, trace, c->m_id, "{}", nread);

        if (nread < 0) {
            c->do_close();
            return;
        }

        assert(buf->base == (char *) c->m_incoming_buf);
        c->m_parser.push_data({c->m_incoming_buf, (size_t) nread});

        Uint8Vector payload;
        while (c->m_parser.next_payload(payload)) {
            uv_timer_again(c->m_idle_timer);

            auto *w = new Work(c, std::move(payload));

            uv_queue_work(stream->loop, &w->req, work_cb, after_work_cb);
            c->m_pending_works.insert(w);

            if (!c->m_persistent) { // Stop after the first request
                uv_read_stop(stream);
                break;
            }
        }
    }

    static void work_cb(uv_work_t *w_req) {
        auto *w = (Work *) w_req->data;
        if (w->cancelled) {
            return;
        }
        auto *conn = w->connection;
        sockaddr_storage ss{};
        int namelen = sizeof(ss);
        uv_tcp_getpeername(conn->m_tcp, (sockaddr *) &ss, &namelen);

        DnsMessageInfo info{.proto = ag::utils::TP_TCP, .peername = SocketAddress{(sockaddr *) &ss}};
        w->payload = conn->m_proxy->handle_message({w->payload.data(), w->payload.size()}, &info);
    }

    static void after_work_cb(uv_work_t *w_req, int status) {
        auto *w = (Work *) w_req->data;
        if (w->cancelled) { // Connection already closed
            delete w;
            return;
        }
        auto *conn = w->connection;
        conn->m_pending_works.erase(w);
        if (w->payload.empty()) {
            if (!conn->m_persistent) {
                conn->do_close();
            }
            delete w;
            return;
        }
        conn->do_write(std::move(w->payload));
        delete w;
    }

    static void write_cb(uv_write_t *w_req, int status) {
        auto *w = (Write *) w_req->data;
        auto *h = (uv_handle_t *) w_req->handle;
        auto *c = (TcpDnsConnection *) h->data;
        // `c` might be nullptr at this point, e.g. the connection was closed,
        // but libuv still called the pending write callbacks.
        if (c) {
            log_id(c->m_log, trace, c->m_id, "{}", status);
            if (!c->m_persistent || status < 0) {
                c->do_close();
            }
        }
        delete w;
    }

    static void idle_timeout_cb(uv_timer_t *h) {
        auto *c = (TcpDnsConnection *) h->data;
        c->do_close();
    }

    void do_read() {
        if (uv_read_start((uv_stream_t *) m_tcp, alloc_cb, read_cb) < 0) {
            do_close();
            return;
        }
        uv_timer_start(m_idle_timer, idle_timeout_cb, m_idle_timeout.count(), m_idle_timeout.count());
    }

    void do_write(Uint8Vector &&payload) {
        auto *w = new Write(std::move(payload));
        if (uv_write(&w->req, (uv_stream_t *) m_tcp, w->bufs, 2, write_cb) < 0) {
            delete w;
            do_close();
        }
    }

    static void close_cb(uv_handle_t *h) {
        free(h);
    }

    void do_close() {
        if (m_closed) {
            return;
        }
        m_closed = true;

        log_id(m_log, trace, m_id, "...");
        uv_timer_stop(m_idle_timer);

        m_idle_timer->data = nullptr;
        uv_close((uv_handle_t *) m_idle_timer, close_cb);

        std::for_each(m_pending_works.begin(), m_pending_works.end(), [](Work *w) {
            w->cancelled = true;
            uv_cancel((uv_req_t *) &w->req);
        });

        m_tcp->data = nullptr;
        uv_close((uv_handle_t *) m_tcp, close_cb);

        if (m_close_callback) {
            m_close_callback(m_id);
        }
    }
};

class TcpListener : public ListenerBase {
private:
    static constexpr auto BACKLOG = 128;

    uv_tcp_t m_tcp_handle{};
    uint64_t m_id_counter{0};
    HashMap<uint64_t, std::unique_ptr<TcpDnsConnection>> m_connections;

    static void conn_cb(uv_stream_t *server, int status) {
        auto *self = (TcpListener *) server->data;

        if (status < 0) {
            log_listener(self, dbg, "Connection failed: {}", uv_strerror(status));
            return;
        }

        auto conn = std::make_unique<TcpDnsConnection>(self->m_id_counter++);

        int err = uv_tcp_init(self->m_loop.get(), conn->handle());
        if (err < 0) {
            log_listener(self, dbg, "uv_tcp_init failed: {}", uv_strerror(err));
            return;
        }

        if ((err = uv_accept(server, (uv_stream_t *) conn->handle())) < 0) {
            log_listener(self, dbg, "uv_accept failed: {}", uv_strerror(err));
            return;
        }

        conn->start(self->m_loop.get(), self->m_proxy, self->m_settings.persistent, self->m_settings.idle_timeout,
                [self](uint64_t id) {
                    self->m_connections.erase(id);
                });
        self->m_connections[conn->id()] = std::move(conn);
    }

protected:
    ErrString before_run() override {
        int err = 0;

        if ((err = uv_tcp_init(m_loop.get(), &m_tcp_handle)) < 0) {
            return AG_FMT("uv_tcp_init failed: {}", uv_strerror(err));
        }
        m_tcp_handle.data = this;

        if (m_settings.fd == -1) {
            if ((err = uv_tcp_bind(&m_tcp_handle, m_address.c_sockaddr(), 0)) < 0) {
                uv_close((uv_handle_t *) &m_tcp_handle, nullptr);
                return AG_FMT("uv_tcp_bind failed: {}", uv_strerror(err));
            }
        } else {
            if ((err = uv_tcp_open(&m_tcp_handle, m_settings.fd)) < 0) {
                uv_close((uv_handle_t *) &m_tcp_handle, nullptr);
                return AG_FMT("uv_tcp_open failed: {}", uv_strerror(err));
            }
            m_settings.fd = -1; // uv_tcp_open took ownership
        }

        if ((err = uv_listen((uv_stream_t *) &m_tcp_handle, BACKLOG, conn_cb)) < 0) {
            uv_close((uv_handle_t *) &m_tcp_handle, nullptr);
            return AG_FMT("uv_listen failed: {}", uv_strerror(err));
        }

        if (m_address.port() == 0) {
            sockaddr_storage name{};
            int namelen = sizeof(name);
            uv_tcp_getsockname(&m_tcp_handle, (sockaddr *) &name, &namelen);
            m_address = SocketAddress((sockaddr *) &name);
        }
        log_listener(this, info, "Listening on {} (TCP)", m_address.str());

        return std::nullopt;
    }

    void before_stop() override {
        uv_close((uv_handle_t *) &m_tcp_handle, nullptr);
        for (auto i = m_connections.begin(); i != m_connections.end();) {
            // close removes current element from the list
            auto next = i;
            std::advance(next, 1);
            i->second->close();
            i = next;
        }
    }
};

DnsProxyListener::CreateResult DnsProxyListener::create_and_listen(const ListenerSettings &settings, DnsProxy *proxy) {
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

    auto err = ptr->init(settings, proxy);
    if (err.has_value()) {
        return {nullptr, err};
    }

    return {std::move(ptr), std::nullopt};
}

} // namespace ag
