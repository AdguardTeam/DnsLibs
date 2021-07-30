#include "dns_framed.h"
#include <vector>
#include <string>
#include <ldns/wire2host.h>
#include <ag_socket_address.h>
#include <ag_logger.h>
#include <ag_utils.h>
#include <ag_socket.h>
#include <ag_tcp_dns_buffer.h>


#define log_conn(l_, lvl_, conn_, fmt_, ...) lvl_##log(l_, "[id={} addr={}] " fmt_, conn_->m_id, conn_->address.str(), ##__VA_ARGS__)


using namespace std::chrono;

using dns_framed_connection_ptr = std::shared_ptr<ag::dns_framed_connection>;


/**
 * DNS framed connection class.
 * It uses format specified in DNS RFC for TCP connections:
 * - Header is 2 bytes - length of payload
 * - Payload is DNS packet content as sent by UDP
 */
class ag::dns_framed_connection : public connection,
        public std::enable_shared_from_this<dns_framed_connection> {
public:
    static constexpr std::string_view UNEXPECTED_EOF = "Unexpected EOF";

    dns_framed_connection(dns_framed_pool *pool, uint32_t id, const upstream *upstream, const socket_address &address);
    void start(std::unique_ptr<SSL, ftor<&SSL_free>> ssl, milliseconds timeout);

    ~dns_framed_connection() override;

    err_string wait_connect_result(int request_id, std::chrono::milliseconds timeout) override;
    err_string write(int request_id, uint8_view buf) override;
    read_result read(int request_id, std::chrono::milliseconds timeout) override;

    /** Logger */
    logger m_log;
    /** Connection id */
    uint32_t m_id;
    /** Connection pool */
    dns_framed_pool *m_pool;
    /** Input buffer */
    tcp_dns_buffer m_input_buffer;
    /** Connection handle */
    socket_factory::socket_ptr m_stream;
    /** Mutex for syncronizing reads and access */
    std::recursive_mutex m_mutex;
    /** Conditional variable for waiting reads */
    std::condition_variable_any m_cond;
    bool m_connected = false;
    /** Set to true when EOF is received or connection is considered inoperable anymore
     *  by inner logic (timeout, error, etc.) */
    bool m_closed = false;
    /** Map of requests to their results */
    hash_map<int, std::optional<read_result>> m_requests;
    /** Number of currently pending requests */
    int m_pending_requests_count = 0;
    /** Signals when all requests completed */
    std::condition_variable_any m_no_requests_cond;

    static void on_connected(void *arg);
    static void on_read(void *arg, uint8_view data);
    static void on_close(void *arg, std::optional<socket::error> error);
};

ag::err_string ag::dns_framed_connection::wait_connect_result(int request_id, std::chrono::milliseconds timeout) {
    log_conn(m_log, trace, this, "{} request={} timeout={}", __func__, request_id, timeout);
    dns_framed_connection_ptr ptr = shared_from_this();
    std::unique_lock l(m_mutex);

    ++m_pending_requests_count;
    utils::scope_exit request_unregister(
            [this] () {
                std::scoped_lock lock(m_mutex);
                if (0 == --m_pending_requests_count) {
                    m_no_requests_cond.notify_one();
                }
            });
    auto &new_request = m_requests[request_id];
    if (m_closed) {
        new_request = read_result{.error = "Already closed"};
    }

    bool have_result = m_cond.wait_until(l, steady_clock::now() + timeout,
            [this] () { return m_closed || m_connected; });

    if (decltype(m_requests)::node_type result_node;
            m_closed && !(result_node = m_requests.extract(request_id)).empty()) {
        std::optional<read_result> &result = result_node.mapped();
        assert(result.has_value());
        return result.has_value() ? result->error : err_string(UNEXPECTED_EOF);
    }

    if (!have_result || m_closed) {
        l.unlock();
        // Request timed out, don't accept new connections on this endpoint
        m_pool->remove_from_all(shared_from_this());
        l.lock();
        return std::string(TIMEOUT_STR);
    }

    l.unlock();
    return std::nullopt;
}

ag::err_string ag::dns_framed_connection::write(int request_id, uint8_view buf) {
    log_conn(m_log, trace, this, "{} request={} len={}", __func__, request_id, buf.size());
    dns_framed_connection_ptr ptr = shared_from_this();

    {
        std::scoped_lock l(m_mutex);

        if (m_closed) {
            std::string msg = AG_FMT("{}: connection already closed", __func__);
            log_conn(m_log, trace, this, "{}", msg);
            return std::move(msg);
        }

        if (std::optional<socket::error> e = m_stream->send_dns_packet(buf); e.has_value()) {
            return std::move(e->description);
        }
    }
    log_conn(m_log, trace, this, "Request submitted {}", request_id);
    return std::nullopt;
}

ag::dns_framed_connection::dns_framed_connection(dns_framed_pool *pool, uint32_t id,
        const upstream *upstream, const socket_address &address)
    : connection(address)
    , m_log(create_logger(__func__))
    , m_id(id)
    , m_pool(pool)
    , m_stream(upstream->make_socket(utils::TP_TCP))
{
}

void ag::dns_framed_connection::start(std::unique_ptr<SSL, ftor<&SSL_free>> ssl, std::chrono::milliseconds timeout) {
    m_pool->m_loop->submit([this, ssl = ssl.release(), timeout] () mutable {
        auto err = m_stream->connect({ m_pool->m_loop.get(), this->address,
                                       { on_connected, on_read, on_close, this },
                                       timeout, std::unique_ptr<SSL, ftor<&SSL_free>>(ssl) });
        if (err.has_value()) {
            log_conn(m_log, err, this, "Failed to start connect: {}", err->description);
            on_close(this, { { -1, "Failed to start connect" } });
        }
    });
}

ag::dns_framed_connection::~dns_framed_connection() {
    std::unique_lock lock(m_mutex);
    m_no_requests_cond.wait(lock,
        [this] () -> bool {
            return m_pending_requests_count == 0;
        });
}

void ag::dns_framed_connection::on_connected(void *arg) {
    auto *self = (dns_framed_connection *)arg;
    log_conn(self->m_log, trace, self, "{}", __func__);
    dns_framed_connection_ptr ptr = self->shared_from_this();

    if (std::unique_lock l(self->m_mutex); self->m_closed) {
        log_conn(self->m_log, trace, self, "Already closed");
        return;
    }

    self->m_pool->add_connected(ptr);
    self->m_connected = true;
    self->m_cond.notify_all();
    log_conn(self->m_log, trace, self, "{} finished", __func__);
}

void ag::dns_framed_connection::on_read(void *arg, uint8_view data) {
    auto *self = (dns_framed_connection *)arg;
    log_conn(self->m_log, trace, self, "{}", __func__);
    dns_framed_connection_ptr ptr = self->shared_from_this();

    if (std::unique_lock l(self->m_mutex); self->m_closed) {
        log_conn(self->m_log, trace, self, "Already closed");
        return;
    }

    while (!data.empty()) {
        data = self->m_input_buffer.store(data);

        std::optional<std::vector<uint8_t>> packet = self->m_input_buffer.extract_packet();
        if (!packet.has_value()) {
            return;
        }

        int id = ntohs(*(uint16_t *)packet->data());
        log_conn(self->m_log, trace, self, "Got response for {}", id);

        std::unique_lock l(self->m_mutex);
        auto found = self->m_requests.find(id);
        if (found != self->m_requests.end()) {
            found->second = { std::move(packet.value()) };
        }
        self->m_cond.notify_all();
    }

    log_conn(self->m_log, trace, self, "{} finished", __func__);
}

void ag::dns_framed_connection::on_close(void *arg, std::optional<socket::error> error) {
    auto *self = (dns_framed_connection *)arg;
    log_conn(self->m_log, trace, self, "{}", __func__);
    dns_framed_connection_ptr ptr = self->shared_from_this();

    if (std::unique_lock l(self->m_mutex); self->m_closed) {
        log_conn(self->m_log, trace, self, "Already closed");
        return;
    }

    if (error.has_value()) {
        log_conn(self->m_log, trace, self, "{} error {} ({})", __func__, error->description, error->code);
    }
    self->m_pool->remove_from_all(self->shared_from_this());
    std::unique_lock l(self->m_mutex);
    self->m_closed = true;
    for (auto &[_, result] : self->m_requests) {
        // do not assign error, if we already got response
        if (!result.has_value()) {
            // Set result
            result = { {}, { error.has_value() ? std::move(error->description) : std::string(UNEXPECTED_EOF) } };
        }
    }
    self->m_cond.notify_all();

    log_conn(self->m_log, trace, self, "{} finished", __func__);
}

ag::connection::read_result ag::dns_framed_connection::read(int request_id, milliseconds timeout) {
    dns_framed_connection_ptr ptr = shared_from_this();
    std::unique_lock l(m_mutex);

    if (m_closed) {
        std::string msg = AG_FMT("{}: connection already closed", __func__);
        log_conn(m_log, trace, this, "{}", msg);
        return { {}, msg };
    }

    ++m_pending_requests_count;
    utils::scope_exit request_unregister(
        [this] () {
            std::scoped_lock lock(m_mutex);
            if (0 == --m_pending_requests_count) {
                m_no_requests_cond.notify_one();
            }
        });

    bool request_replied = m_cond.wait_until(l, steady_clock::now() + timeout, [&]{
        const auto it = m_requests.find(request_id);
        return it != m_requests.end() && (*it).second.has_value();
    });

    if (!request_replied) {
        l.unlock();
        // Request timed out, don't accept new connections on this endpoint
        m_pool->remove_from_all(shared_from_this());
        l.lock();
        return {{}, {"Timed out"}};
    }
    auto result_node = m_requests.extract(request_id);
    return result_node.mapped().value();
}

void ag::dns_framed_pool::add_connected(const connection_ptr &ptr) {
    dns_framed_connection *conn = (dns_framed_connection *)ptr.get();
    log_conn(conn->m_log, trace, conn, "{}", __func__);

    std::scoped_lock l(m_mutex);
    m_pending_connections.erase(ptr);
    m_connections.push_back(ptr);
}

void ag::dns_framed_pool::remove_from_all(const connection_ptr &ptr) {
    dns_framed_connection *conn = (dns_framed_connection *)ptr.get();
    log_conn(conn->m_log, trace, conn, "{}", __func__);

    std::scoped_lock l(m_mutex);
    m_pending_connections.erase(ptr);
    m_connections.remove(ptr);

    if (!conn->m_closed) {
        close_connection(ptr);
    }
}

void ag::dns_framed_pool::add_pending_connection(const connection_ptr &ptr) {
    dns_framed_connection *conn = (dns_framed_connection *)ptr.get();
    log_conn(conn->m_log, trace, conn, "{}", __func__);

    m_pending_connections.insert(ptr);
}

ag::connection_ptr ag::dns_framed_pool::create_connection(std::unique_ptr<SSL, ftor<&SSL_free>> ssl, const socket_address &address) {
    static std::atomic_uint32_t conn_id{0};
    auto ptr = std::make_shared<dns_framed_connection>(this, conn_id++, m_upstream, address);
    ptr->start(std::move(ssl), m_upstream->options().timeout);
    return ptr;
}

// A connection should be deleted on the event loop, but some events may raise on already
// scheduled to delete one. That means that we should increment the reference counter until
// delete event is called.
void ag::dns_framed_pool::close_connection(const connection_ptr &conn) {
    dns_framed_connection *framed_conn = (dns_framed_connection *)conn.get();
    {
        std::scoped_lock l(framed_conn->m_mutex);
        framed_conn->m_closed = true;
        for (auto &[_, result] : framed_conn->m_requests) {
            // do not assign error, if we already got response
            if (!result.has_value()) {
                result = { {}, { "Connection has been forcibly closed" } };
            }
        }
        framed_conn->m_cond.notify_all();
    }
    m_closing_connections.emplace(conn);

    [[maybe_unused]] auto err = framed_conn->m_stream->set_callbacks({});

    m_loop->submit([this, c = conn] () {
        std::scoped_lock l(m_mutex);
        m_closing_connections.erase(c);
        if (m_closing_connections.empty()) {
            m_no_conns_cond.notify_one();
        }
    });
}

ag::dns_framed_pool::dns_framed_pool(event_loop_ptr loop, upstream *upstream)
    : m_loop(std::move(loop))
    , m_upstream(upstream)
    , m_log(create_logger(__func__))
{}

ag::dns_framed_pool::~dns_framed_pool() {
    dbglog(m_log, "Destroying...");

    std::unique_lock l(m_mutex);

    for (const connection_ptr & conn : m_connections) {
        close_connection(conn);
    }
    m_connections.clear();
    for (const connection_ptr & conn : m_pending_connections) {
        close_connection(conn);
    }
    m_pending_connections.clear();

    dbglog(m_log, "Waiting until all connections are closed...");
    m_no_conns_cond.wait(l,
            [this] () -> bool {
                return m_connections.empty() && m_pending_connections.empty() && m_closing_connections.empty();
            });
    m_loop.reset();

    dbglog(m_log, "Destroyed");
}

ag::connection::read_result ag::dns_framed_pool::perform_request_inner(uint8_view buf, milliseconds timeout) {
    auto[conn, elapsed, err] = get();
    if (!conn) {
        return { {}, std::move(err) };
    }

    if (buf.size() < 2) {
        return { {}, "Too short request" };
    }

    timeout -= duration_cast<milliseconds>(elapsed);
    if (timeout <= milliseconds(0)) {
        return { {}, AG_FMT("DNS server name resolving took too much time: {}", elapsed) };
    }

    utils::timer timer;

    uint16_t id = ntohs(*(uint16_t *)buf.data());
    if (err_string e = conn->wait_connect_result(id, timeout); e.has_value()) {
        return { {}, std::move(e) };
    }

    timeout -= timer.elapsed<decltype(timeout)>();
    if (timeout.count() <= 0) {
        return { {}, AG_FMT("Connect to DNS server took too much time: {}", timer.elapsed<decltype(timeout)>()) };
    }

    if (err_string e = conn->write(id, buf); e.has_value()) {
        return { {}, std::move(e) };
    }

    return conn->read(id, timeout);
}

ag::connection::read_result ag::dns_framed_pool::perform_request(uint8_view buf, milliseconds timeout) {
    utils::timer timer;
    connection::read_result result = perform_request_inner(buf, timeout);
    // try one more time in case of the server closed the connection before we got the response
    // https://github.com/AdguardTeam/DnsLibs/issues/24
    if (result.error.has_value() && result.error.value() == dns_framed_connection::UNEXPECTED_EOF) {
        timeout -= timer.elapsed<milliseconds>();
        if (timeout < milliseconds(0)) {
            result.error.emplace(TIMEOUT_STR.data());
        } else {
            result = perform_request_inner(buf, timeout);
        }
    }
    return result;
}
