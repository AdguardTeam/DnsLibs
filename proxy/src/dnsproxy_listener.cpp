#include "dnsproxy_listener.h"

#include <ag_socket_address.h>
#include <uv.h>
#include <thread>
#include <atomic>
#include <magic_enum.hpp>
#include <algorithm>
#include <cassert>

// Set the libuv thread pool size. Must happen before any libuv usage to have effect.
static const int THREAD_POOL_SIZE_RESULT [[maybe_unused]] = uv_os_setenv("UV_THREADPOOL_SIZE", "128");

// This is for incoming request packets.
// RFC 6891 6.2.5 recommends clients to assume that packets of up to 4096 bytes are supported.
// If the upstream supports less, it will say so in its response, which we forward to the requestor.
// If the upstream supports more, and the requestor decides to take advantage of that,
// it's out of luck with our proxy.
// We could specify LDNS_MAX_PACKETLEN here, but that would waste a lot of memory since most request
// packets are going to be small anyway
// (remember, this constant only affects incoming packets, we always send back as much as the upstream returned)
static constexpr size_t UDP_RECV_BUF_SIZE = 4096;

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
class listener_base : public ag::dnsproxy_listener {
protected:
    ag::logger m_log;
    ag::dnsproxy *m_proxy{nullptr};
    std::thread m_loop_thread;
    uv_loop_t m_loop{};
    uv_async_t m_escape_hatch{};
    ag::socket_address m_address;
    ag::listener_settings m_settings;

    // Subclass initializes its handles, callbacks, etc.
    // The loop is initialized, but isn't yet running at this point
    // Called on event loop's thread
    // Return nullopt if the loop should run (success)
    virtual ag::err_string before_run() = 0;

    // Subclass cleans up to allow the event loop to exit
    // (close handles, cancel pending work, etc.)
    // Called on event loop's thread
    virtual void before_stop() = 0;

private:
    static void escape_hatch_cb(uv_async_t *handle) {
        auto *self = (listener_base *) handle->data;
        self->before_stop();
        uv_close((uv_handle_t *) &self->m_escape_hatch, nullptr);
    }

public:
    /**
     * @return std::nullopt if ok, error string otherwise
     */
    ag::err_string init(const ag::listener_settings &settings, ag::dnsproxy *proxy) {
        m_proxy = proxy;
        if (!m_proxy) {
            return "Proxy is not set";
        }

        // Parse the address
        m_address = ag::socket_address({settings.address.data(), settings.address.size()});
        if (!m_address.valid()) {
            return fmt::format("Failed to parse address: {}", settings.address);
        }
        const auto addr = m_address.addr();
        m_address = ag::socket_address({addr.data(), addr.size()}, settings.port); // Assume won't fail

        m_log = ag::create_logger(fmt::format("listener({} {})",
                                              magic_enum::enum_name(settings.protocol),
                                              m_address.str()));

        m_settings = settings;

        int err = 0;
        // Init the loop
        if ((err = uv_loop_init(&m_loop)) < 0) {
            return fmt::format("uv_loop_init failed: {}", uv_strerror(err));
        }

        // Init the escape hatch
        if ((err = uv_async_init(&m_loop, &m_escape_hatch, escape_hatch_cb))) {
            return fmt::format("uv_async_init failed: {}", uv_strerror(err));
        }
        m_escape_hatch.data = this;

        const auto err_str = before_run();
        if (err_str.has_value()) {
            return err_str;
        }

        m_loop_thread = std::thread([this]() {
            infolog(m_log, "Listening on {} ({})", m_address.str(), magic_enum::enum_name(m_settings.protocol));
            uv_run(&m_loop, UV_RUN_DEFAULT);
            infolog(m_log, "Finished listening");
        });

        return std::nullopt;
    }

    ~listener_base() override {
        await_shutdown();
    }

    void shutdown() final {
        // The next invocation of escape_hatch_cb will close all handles, allowing the loop to exit
        if (this == m_escape_hatch.data) { // Check async initialized
            uv_async_send(&m_escape_hatch);
        }
    }

    void await_shutdown() final {
        if (m_loop_thread.joinable()) { // Allow await_shutdown() to be called more than once
            m_loop_thread.join();
        }
    }
};

class listener_udp : public listener_base {
private:
    struct task {
        uv_work_t work_req{};
        listener_udp *self;
        ag::socket_address peer;
        uv_buf_t request;
        ag::uint8_vector response; // Filled in work_cb

        // Takes ownership of request buffer
        task(listener_udp *self, const sockaddr *addr, uv_buf_t request)
                : self(self), peer(addr), request(request) {

            work_req.data = this;
        }

        ~task() {
            dealloc_buf(&request);
        }
    };

    uv_udp_t m_udp_handle{};
    ag::hash_set<task *> m_pending; // Messages not yet processed by the proxy

    static void work_cb(uv_work_t *req) {
        auto *m = (task *) req->data;
        m->response = m->self->m_proxy->handle_message({(uint8_t *) m->request.base, m->request.len});
    }

    static void send_cb(uv_udp_send_t *req, int status) {
        auto *m = (task *) req->data;
        if (status != 0) {
            dbglog(m->self->m_log, "{} error: {}", __func__, uv_strerror(status));
        }
        delete req;
        delete m;
    }

    static void after_work_cb(uv_work_t *req, int status) {
        auto *m = (task *) req->data;

        m->self->m_pending.erase(m);

        if (status == UV_ECANCELED) {
            delete m;
            return;
        }

        auto resp_buf = uv_buf_init((char *) m->response.data(), m->response.size());

        auto *send_req = new uv_udp_send_t;
        send_req->data = m;

        const int err = uv_udp_send(send_req, &m->self->m_udp_handle, &resp_buf, 1, m->peer.c_sockaddr(), send_cb);
        if (err < 0) {
            dbglog(m->self->m_log, "uv_udp_send failed: {}", uv_strerror(err));
            delete send_req;
            delete m;
        }
    }

    static void recv_cb(uv_udp_t *handle, ssize_t nread, const uv_buf_t *buf,
                        const struct sockaddr *addr, unsigned flags) {
        auto *self = (listener_udp *) handle->data;

        if (nread < 0) {
            dbglog(self->m_log, "{} failed: {}", __func__, uv_strerror(nread));
            dealloc_buf(buf);
            return;
        }
        if (nread == 0) {
            dbglog(self->m_log, "{}: received empty packet", __func__);
            dealloc_buf(buf);
            return;
        }
        if (flags & UV_UDP_PARTIAL) {
            dbglog(self->m_log, "{} failed: truncated", __func__);
            dealloc_buf(buf);
            return;
        }

        auto *m = new task(self, addr, *buf);
        uv_queue_work(&self->m_loop, &m->work_req, work_cb, after_work_cb);
        self->m_pending.insert(m);
    }

protected:
    ag::err_string before_run() override {
        int err = 0;

        // Init UDP
        if ((err = uv_udp_init(&m_loop, &m_udp_handle)) < 0) {
            return fmt::format("uv_udp_init failed: {}", uv_strerror(err));
        }
        m_udp_handle.data = this;

        if ((err = uv_udp_bind(&m_udp_handle, m_address.c_sockaddr(), UV_UDP_REUSEADDR)) < 0) {
            return fmt::format("uv_udp_bind failed: {}", uv_strerror(err));
        }

        if ((err = uv_udp_recv_start(&m_udp_handle, udp_alloc_cb, recv_cb)) < 0) {
            return fmt::format("uv_udp_recv_start failed: {}", uv_strerror(err));
        }

        return std::nullopt;
    }

    void before_stop() override {
        uv_close((uv_handle_t *) &m_udp_handle, nullptr);

        for (auto *m : m_pending) {
            uv_cancel((uv_req_t *) &m->work_req);
        }
    }
};

class tcp_dns_payload_parser {
private:
    enum class state {
        RD_SIZE, RD_PAYLOAD
    };
    state m_state;
    uint16_t m_size;
    ag::uint8_vector m_data;

public:
    tcp_dns_payload_parser() : m_state{state::RD_SIZE}, m_size{0} {
    }

    // Push more data to this parser
    void push_data(ag::uint8_view data) {
        m_data.insert(m_data.end(), data.begin(), data.end());
    }

    // Initialize `out` to contain the next parsed payload
    // Return true if successful or false if more data is needed (in which case `out` won't be modified)
    bool next_payload(ag::uint8_vector &out) {
        if (m_state == state::RD_SIZE) {
            if (m_data.size() < 2) {
                return false; // Need more data
            }
            m_size = *(uint16_t *) m_data.data();
            m_size = ntohs(m_size);
            m_state = state::RD_PAYLOAD;
        }
        if (m_state == state::RD_PAYLOAD) {
            if (m_data.size() < 2 + m_size) {
                return false; // Need more data
            }
            out = ag::uint8_vector(m_data.begin() + 2, m_data.begin() + 2 + m_size);
            m_data.erase(m_data.begin(), m_data.begin() + 2 + m_size);
            m_state = state::RD_SIZE;
        }
        return true;
    }
};

class tcp_dns_connection {
public:
    explicit tcp_dns_connection(uint64_t id) : m_id{id} {
        this->m_tcp = new uv_tcp_t; // Deleted in close_cb
        this->m_tcp->data = this;

        this->m_idle_timer = new uv_timer_t; // Deleted in close_cb
        this->m_idle_timer->data = this;
    }

    // Call after *handle() is properly initialized
    void start(uv_loop_t *loop,
               ag::dnsproxy *proxy,
               bool persistent,
               std::chrono::milliseconds idle_timeout,
               std::function<void(uint64_t)> close_callback) {

        assert(proxy);
        assert(idle_timeout.count());

        ++m_open_handles; // m_tcp

        uv_timer_init(loop, m_idle_timer);
        ++m_open_handles;

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
    struct work {
        uv_work_t req{};
        tcp_dns_connection *c;
        ag::uint8_vector payload;
        bool canceled;
        std::mutex mtx;

        work(tcp_dns_connection *c, ag::uint8_vector &&payload)
                : c{c},
                  payload{std::move(payload)},
                  canceled{false} {
            this->req.data = this;
        }
    };

    struct write {
        uv_write_t req{};
        tcp_dns_connection *c;
        ag::uint8_vector payload;
        uint16_t size_be; // Big-endian size
        uv_buf_t bufs[2];

        write(tcp_dns_connection *c, ag::uint8_vector &&payload) : c(c), payload(std::move(payload)) {
            this->req.data = this;
            this->size_be = this->payload.size();
            this->size_be = htons(this->size_be);
            bufs[0] = uv_buf_init((char *) &this->size_be, sizeof(this->size_be));
            bufs[1] = uv_buf_init((char *) this->payload.data(), this->payload.size());
        }
    };

    const uint64_t m_id;
    ag::dnsproxy *m_proxy{};
    bool m_persistent{false};
    uint8_t m_incoming_buf[TCP_RECV_BUF_SIZE]{};
    uv_tcp_t *m_tcp{};
    uv_timer_t *m_idle_timer{};
    std::chrono::milliseconds m_idle_timeout{0};
    std::function<void(uint64_t)> m_close_callback;
    bool m_closed{false};
    tcp_dns_payload_parser m_parser;
    ag::hash_set<work *> m_pending_works;
    size_t m_open_handles{0};

    static void alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
        auto *c = (tcp_dns_connection *) handle->data;
        buf->base = (char *) c->m_incoming_buf;
        buf->len = sizeof(c->m_incoming_buf);
    }

    static void read_cb(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
        auto *c = (tcp_dns_connection *) stream->data;

        if (nread < 0) {
            c->do_close();
            return;
        }

        assert(buf->base == (char *) c->m_incoming_buf);
        c->m_parser.push_data({c->m_incoming_buf, (size_t) nread});

        ag::uint8_vector payload;
        while (c->m_parser.next_payload(payload)) {
            uv_timer_again(c->m_idle_timer);

            auto *w = new work(c, std::move(payload));

            uv_queue_work(stream->loop, &w->req, work_cb, after_work_cb);
            c->m_pending_works.insert(w);

            if (!c->m_persistent) { // Stop after the first request
                uv_read_stop(stream);
                break;
            }
        }
    }

    static void work_cb(uv_work_t *w_req) {
        auto *w = (work *) w_req->data;
        std::scoped_lock l{w->mtx};
        if (w->canceled) {
            return;
        }
        auto *c = w->c;
        w->payload = c->m_proxy->handle_message({w->payload.data(), w->payload.size()});
    }

    static void after_work_cb(uv_work_t *w_req, int status) {
        auto *w = (work *) w_req->data;
        std::scoped_lock l{w->mtx};
        if (status == 0 && !w->canceled) {
            auto *c = w->c;
            c->m_pending_works.erase(w);
            c->do_write(std::move(w->payload));
        }
        delete w;
    }

    static void write_cb(uv_write_t *w_req, int status) {
        auto *w = (write *) w_req->data;
        auto *c = w->c;
        if (status < 0 || !c->m_persistent) {
            c->do_close();
        }
        delete w;
    }

    static void idle_timeout_cb(uv_timer_t *h) {
        auto *c = (tcp_dns_connection *) h->data;
        c->do_close();
    }

    void do_read() {
        if (uv_read_start((uv_stream_t *) m_tcp, alloc_cb, read_cb) < 0) {
            do_close();
            return;
        }
        uv_timer_start(m_idle_timer, idle_timeout_cb, m_idle_timeout.count(), m_idle_timeout.count());
    }

    void do_write(ag::uint8_vector &&payload) {
        auto *w = new write(this, std::move(payload));
        if (uv_write(&w->req, (uv_stream_t *) m_tcp, w->bufs, 2, write_cb) < 0) {
            delete w;
            do_close();
        }
    }

    static void close_cb(uv_handle_t *h) {
        delete h;
    }

    void do_close() {
        if (m_closed) {
            return;
        }
        m_closed = true;

        uv_timer_stop(m_idle_timer);

        m_idle_timer->data = nullptr;
        uv_close((uv_handle_t *) m_idle_timer, close_cb);

        std::for_each(m_pending_works.begin(), m_pending_works.end(), [](work *w) {
            std::scoped_lock l{w->mtx};
            uv_cancel((uv_req_t *) &w->req);
            w->canceled = true;
        });

        m_tcp->data = nullptr;
        uv_close((uv_handle_t *) m_tcp, close_cb);

        if (m_close_callback) {
            m_close_callback(m_id);
        }
    }
};

class listener_tcp : public listener_base {
private:
    static constexpr auto BACKLOG = 128;

    uv_tcp_t m_tcp_handle{};
    uint64_t m_id_counter{0};
    ag::hash_map<uint64_t, std::unique_ptr<tcp_dns_connection>> m_connections;

    static void conn_cb(uv_stream_t *server, int status) {
        auto *self = (listener_tcp *) server->data;
        tracelog(self->m_log, "{}: started", __func__);

        if (status < 0) {
            dbglog(self->m_log, "{}: connection failed: {}", __func__, uv_strerror(status));
            return;
        }

        auto conn = std::make_unique<tcp_dns_connection>(self->m_id_counter++);

        int err = uv_tcp_init(&self->m_loop, conn->handle());
        if (err < 0) {
            dbglog(self->m_log, "{}: uv_tcp_init failed: {}", __func__, uv_strerror(err));
            return;
        }

        if ((err = uv_accept(server, (uv_stream_t *) conn->handle())) < 0) {
            dbglog(self->m_log, "{}: uv_accept failed: {}", __func__, uv_strerror(err));
            return;
        }

        conn->start(&self->m_loop,
                    self->m_proxy,
                    self->m_settings.persistent,
                    self->m_settings.idle_timeout,
                    [self](uint64_t id) {
                        self->m_connections.erase(id);
                    });
        self->m_connections[conn->id()] = std::move(conn);
    }

protected:
    ag::err_string before_run() override {
        int err = 0;

        if ((err = uv_tcp_init(&m_loop, &m_tcp_handle)) < 0) {
            return fmt::format("uv_tcp_init failed: {}", uv_strerror(err));
        }
        m_tcp_handle.data = this;

        if ((err = uv_tcp_bind(&m_tcp_handle, m_address.c_sockaddr(), 0)) < 0) {
            return fmt::format("uv_tcp_bind failed: {}", uv_strerror(err));
        }

        if ((err = uv_listen((uv_stream_t *) &m_tcp_handle, BACKLOG, conn_cb)) < 0) {
            return fmt::format("uv_listen failed: {}", uv_strerror(err));
        }

        return std::nullopt;
    }

    void before_stop() override {
        uv_close((uv_handle_t *) &m_tcp_handle, nullptr);
        std::for_each(m_connections.begin(), m_connections.end(), [](auto &kv) { kv.second->close(); });
    }
};

ag::dnsproxy_listener::create_result ag::dnsproxy_listener::create_and_listen(const ag::listener_settings &settings,
                                                                              dnsproxy *proxy) {
    if (!proxy) {
        return {nullptr, "proxy is nullptr"};
    }

    std::unique_ptr<listener_base> ptr;
    switch (settings.protocol) {
    case ag::listener_protocol::UDP:
        ptr = std::make_unique<listener_udp>();
        break;
    case ag::listener_protocol::TCP:
        ptr = std::make_unique<listener_tcp>();
        break;
    default:
        return {nullptr, fmt::format("Protocol {} not implemented", magic_enum::enum_name(settings.protocol))};
    }

    auto err = ptr->init(settings, proxy);
    if (err.has_value()) {
        return {nullptr, err};
    }

    return {std::move(ptr), std::nullopt};
}
