#include "dns_framed.h"
#include <vector>
#include <mutex>
#include <list>
#include <ldns/wire2host.h>
#include <event2/buffer.h>
#include <ag_socket_address.h>
#include <ag_logger.h>
#include <ag_utils.h>


#define log_conn(l_, lvl_, conn_, fmt_, ...) lvl_##log(l_, "[id={} addr={}] " fmt_, conn_->m_id, conn_->address.str(), ##__VA_ARGS__)


using namespace std::chrono;

using bufferevent_ptr = std::unique_ptr<bufferevent, ag::ftor<&bufferevent_free>>;
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

    dns_framed_connection(ag::dns_framed_pool *pool, uint32_t id, bufferevent *bev, const ag::socket_address &address);

    ~dns_framed_connection() override;

    int write(ag::uint8_view buf) override;

    read_result read(int request_id, std::chrono::milliseconds timeout) override;

    /** Logger */
    ag::logger m_log;
    /** Connection id */
    uint32_t m_id;
    /** Connection pool */
    ag::dns_framed_pool *m_pool;
    /** Connection handle */
    bufferevent_ptr m_bev;
    /** Mutex for syncronizing reads and access */
    std::recursive_mutex m_mutex;
    /** Conditional variable for waiting reads */
    std::condition_variable_any m_cond;
    /** Map of requests to their results */
    ag::hash_map<int, std::optional<read_result>> m_requests;
    /** Number of currently called reads */
    int m_pending_reads_count = 0;
    /** Signals when all reads completed */
    std::condition_variable_any m_no_reads_cond;

    void on_read();

    void on_event(int what);
};


int ag::dns_framed_connection::write(uint8_view buf) {
    log_conn(m_log, trace, this, "{} len={}", __func__, buf.size());
    dns_framed_connection_ptr ptr = shared_from_this();
    if (buf.size() < 2) {
        log_conn(m_log, trace, this, "{} returned -1", __func__);
        return -1;
    }
    uint16_t id = ntohs(*(uint16_t *)buf.data());
    {
        std::scoped_lock l(m_mutex);

        using evbuffer_ptr = std::unique_ptr<evbuffer, ftor<&evbuffer_free>>;
        evbuffer_ptr packet_buf{evbuffer_new()};

        uint16_t pkt_len_net = htons((uint16_t) buf.size());
        evbuffer_add(&*packet_buf, &pkt_len_net, 2);
        evbuffer_add(&*packet_buf, buf.data(), buf.size());

        bufferevent_write_buffer(&*m_bev, &*packet_buf);

        m_requests[id] = std::nullopt;
    }
    log_conn(m_log, trace, this, "Request submitted {}", id);
    return id;
}

ag::dns_framed_connection::dns_framed_connection(dns_framed_pool *pool, uint32_t id, bufferevent *bev, const socket_address &address)
        : connection(address)
        , m_log(create_logger(__func__))
        , m_id(id)
        , m_pool(pool)
        , m_bev(bev)
{
    bufferevent_setcb(&*m_bev, [](bufferevent *, void *arg) {
        auto conn = (dns_framed_connection *) arg;
        conn->on_read();
    }, nullptr, [](bufferevent *, short what, void *arg) {
        auto conn = (dns_framed_connection *) arg;
        conn->on_event(what);
    }, this);
    bufferevent_enable(bev, EV_READ | EV_WRITE);
}

ag::dns_framed_connection::~dns_framed_connection() {
    std::unique_lock lock(m_mutex);
    m_no_reads_cond.wait(lock,
        [this] () -> bool {
            return m_pending_reads_count == 0;
        });
}

void ag::dns_framed_connection::on_read() {
    log_conn(m_log, trace, this, "{}", __func__);
    dns_framed_connection_ptr ptr = shared_from_this();

    auto *input = bufferevent_get_input(&*m_bev);
    for (;;) {
        if (evbuffer_get_length(input) < 2) {
            break;
        }
        uint16_t length;
        evbuffer_copyout(input, &length, 2);
        length = ntohs(length);
        if (length < 2) {
            break;
        }
        if (evbuffer_get_length(input) < 2 + length) {
            break;
        }
        evbuffer_drain(input, 2);
        std::vector<uint8_t> buf;
        buf.resize(length);
        evbuffer_remove(input, buf.data(), buf.size());
        int id = ntohs(*(uint16_t *)buf.data());
        {
            std::unique_lock l(m_mutex);
            if (m_requests.count(id)) {
                m_requests.at(id) = {std::move(buf), std::nullopt};
            }
            m_cond.notify_all();
        }
        log_conn(m_log, trace, this, "Got response for {}", id);
    }
    log_conn(m_log, trace, this, "{} finished", __func__);
}

void ag::dns_framed_connection::on_event(int what) {
    log_conn(m_log, trace, this, "{}", __func__);
    dns_framed_connection_ptr ptr = shared_from_this();

    if (what & BEV_EVENT_CONNECTED) {
        log_conn(m_log, trace, this, "{} connected", __func__);
        m_pool->add_connected(shared_from_this());
    }
    if (what & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
        if (what & BEV_EVENT_EOF) {
            log_conn(m_log, trace, this, "{} eof", __func__);
        } else {
            log_conn(m_log, trace, this, "{} error {}", __func__, evutil_socket_error_to_string(evutil_socket_geterror(bufferevent_getfd(m_bev.get()))));
        }
        m_pool->remove_from_all(shared_from_this());
        std::unique_lock l(m_mutex);
        for (auto &entry : m_requests) {
            std::string error = (what & BEV_EVENT_EOF) ? std::string(UNEXPECTED_EOF) :
                                evutil_socket_error_to_string(evutil_socket_geterror(bufferevent_getfd(m_bev.get())));
            // Set result
            entry.second = {std::vector<uint8_t>{}, {std::move(error)}};
        }
        m_cond.notify_all();
    }
    log_conn(m_log, trace, this, "{} finished", __func__);
}

ag::connection::read_result ag::dns_framed_connection::read(int request_id, milliseconds timeout) {
    dns_framed_connection_ptr ptr = shared_from_this();
    std::unique_lock l(m_mutex);

    ++m_pending_reads_count;
    utils::scope_exit read_unregister(
        [this] () {
            std::scoped_lock lock(m_mutex);
            if (0 == --m_pending_reads_count) {
                m_no_reads_cond.notify_one();
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

    close_connection(ptr);
}

void ag::dns_framed_pool::add_pending_connection(const connection_ptr &ptr) {
    dns_framed_connection *conn = (dns_framed_connection *)ptr.get();
    log_conn(conn->m_log, trace, conn, "{}", __func__);

    m_pending_connections.insert(ptr);
}

ag::connection_ptr ag::dns_framed_pool::create_connection(bufferevent *bev, const socket_address &address) {
    static std::atomic_uint32_t conn_id{0};
    return std::make_shared<dns_framed_connection>(this, conn_id++, bev, address);
}

// A connection should be deleted on the event loop, but some events may raise on already
// scheduled to delete one. That means that we should increment the reference counter until
// delete event is called.
void ag::dns_framed_pool::close_connection(const connection_ptr &conn) {
    dns_framed_connection *framed_conn = (dns_framed_connection *)conn.get();

    event_base_once(bufferevent_get_base(framed_conn->m_bev.get()), -1, EV_TIMEOUT,
        [] (evutil_socket_t, short, void *ptr) {
            delete (connection_ptr *)ptr;
        }, new connection_ptr(conn), nullptr);
}

ag::dns_framed_pool::~dns_framed_pool() {
    {
        std::scoped_lock l(m_mutex);
        for (const connection_ptr & conn : m_connections) {
            close_connection(conn);
        }
        m_connections.clear();
        for (const connection_ptr & conn : m_pending_connections) {
            close_connection(conn);
        }
        m_pending_connections.clear();
    }
    m_loop->stop();
    m_loop.reset();
}

ag::connection::read_result ag::dns_framed_pool::perform_request_inner(uint8_view buf, milliseconds timeout) {
    auto[conn, elapsed, err] = get();
    if (!conn) {
        return { {}, std::move(err) };
    }

    timeout -= duration_cast<milliseconds>(elapsed);
    if (timeout < milliseconds(0)) {
        return { {}, AG_FMT("DNS server name resolving took too much time: {}", elapsed) };
    }

    int id = conn->write(buf);
    if (id < 0) {
        return { {}, "Failed to send request" };
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
            result.error.emplace("Timed out");
        } else {
            result = perform_request_inner(buf, timeout);
        }
    }
    return result;
}
