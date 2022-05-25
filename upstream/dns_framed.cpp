#include "dns_framed.h"
#include "common/logger.h"
#include "common/socket_address.h"
#include "common/utils.h"
#include "net/socket.h"
#include "net/tcp_dns_buffer.h"
#include <cassert>
#include <ldns/wire2host.h>
#include <string>
#include <vector>

#define log_conn(l_, lvl_, conn_, fmt_, ...)                                                                           \
    lvl_##log(l_, "[id={} addr={}] " fmt_, conn_->m_id, conn_->address.str(), ##__VA_ARGS__)

using namespace std::chrono;

namespace ag {

using DnsFramedConnectionPtr = std::shared_ptr<DnsFramedConnection>;

/**
 * DNS framed connection class.
 * It uses format specified in DNS RFC for TCP connections:
 * - Header is 2 bytes - length of payload
 * - Payload is DNS packet content as sent by UDP
 */
class DnsFramedConnection : public Connection, public std::enable_shared_from_this<DnsFramedConnection> {
public:
    static constexpr std::string_view UNEXPECTED_EOF = "Unexpected EOF";

    DnsFramedConnection(DnsFramedPool *pool, uint32_t id, const Upstream *upstream, const SocketAddress &address,
            std::optional<SocketFactory::SecureSocketParameters> secure_socket_parameters, Millis idle_timeout);
    void start(Millis timeout);

    ~DnsFramedConnection() override;

    ErrString wait_connect_result(int request_id, Millis timeout) override;
    ErrString write(int request_id, Uint8View buf) override;
    ReadResult read(int request_id, Millis timeout) override;

    /** Logger */
    Logger m_log;
    /** Connection id */
    uint32_t m_id;
    /** Connection pool */
    DnsFramedPool *m_pool;
    /** Input buffer */
    TcpDnsBuffer m_input_buffer;
    /** Connection handle */
    SocketFactory::SocketPtr m_stream;
    /** Idle timeout */
    Millis m_idle_timeout;
    /** Mutex for syncronizing reads and access */
    std::recursive_mutex m_mutex;
    /** Conditional variable for waiting reads */
    std::condition_variable_any m_cond;
    bool m_connected = false;
    /** Set to true when EOF is received or connection is considered inoperable anymore
     *  by inner logic (timeout, error, etc.) */
    bool m_closed = false;
    /** Map of requests to their results */
    HashMap<int, std::optional<ReadResult>> m_requests;
    /** Number of currently pending requests */
    int m_pending_requests_count = 0;
    /** Signals when all requests completed */
    std::condition_variable_any m_no_requests_cond;

    static void on_connected(void *arg);
    static void on_read(void *arg, Uint8View data);
    static void on_close(void *arg, std::optional<Socket::Error> error);
};

ErrString DnsFramedConnection::wait_connect_result(int request_id, Millis timeout) {
    log_conn(m_log, trace, this, "{} request={} timeout={}", __func__, request_id, timeout);
    DnsFramedConnectionPtr ptr = shared_from_this();
    std::unique_lock l(m_mutex);

    ++m_pending_requests_count;
    utils::ScopeExit request_unregister([this]() {
        std::scoped_lock lock(m_mutex);
        if (0 == --m_pending_requests_count) {
            m_no_requests_cond.notify_one();
        }
    });
    auto &new_request = m_requests[request_id];
    if (m_closed) {
        new_request = ReadResult{.error = "Already closed"};
    }

    bool have_result = m_cond.wait_until(l, steady_clock::now() + timeout, [this]() {
        return m_closed || m_connected;
    });

    if (decltype(m_requests)::node_type result_node;
            m_closed && !(result_node = m_requests.extract(request_id)).empty()) {
        std::optional<ReadResult> &result = result_node.mapped();
        assert(result.has_value());
        return result.has_value() ? result->error : ErrString(UNEXPECTED_EOF);
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

ErrString DnsFramedConnection::write(int request_id, Uint8View buf) {
    log_conn(m_log, trace, this, "{} request={} len={}", __func__, request_id, buf.size());
    DnsFramedConnectionPtr ptr = shared_from_this();

    {
        std::scoped_lock l(m_mutex);

        if (m_closed) {
            std::string msg = AG_FMT("{}: connection already closed", __func__);
            log_conn(m_log, trace, this, "{}", msg);
            return std::move(msg);
        }

        if (std::optional<Socket::Error> e = m_stream->send_dns_packet(buf); e.has_value()) {
            return std::move(e->description);
        }
    }
    log_conn(m_log, trace, this, "Request submitted {}", request_id);
    return std::nullopt;
}

DnsFramedConnection::DnsFramedConnection(DnsFramedPool *pool, uint32_t id, const Upstream *upstream,
        const SocketAddress &address, std::optional<SocketFactory::SecureSocketParameters> secure_socket_parameters,
        Millis idle_timeout)
        : Connection(address)
        , m_log(__func__)
        , m_id(id)
        , m_pool(pool)
        , m_stream(secure_socket_parameters.has_value()
                          ? upstream->make_secured_socket(utils::TP_TCP, std::move(secure_socket_parameters.value()))
                          : upstream->make_socket(utils::TP_TCP))
        , m_idle_timeout(idle_timeout) {
}

void DnsFramedConnection::start(Millis timeout) {
    m_pool->m_loop->submit([this, timeout]() mutable {
        std::scoped_lock l(m_mutex);
        auto err = m_stream->connect({
                m_pool->m_loop.get(),
                this->address,
                {on_connected, on_read, on_close, this},
                timeout,
        });
        if (err.has_value()) {
            log_conn(m_log, err, this, "Failed to start connect: {}", err->description);
            on_close(this, {{-1, "Failed to start connect"}});
        }
    });
}

DnsFramedConnection::~DnsFramedConnection() {
    std::unique_lock lock(m_mutex);
    m_no_requests_cond.wait(lock, [this]() -> bool {
        return m_pending_requests_count == 0;
    });
}

void DnsFramedConnection::on_connected(void *arg) {
    auto *self = (DnsFramedConnection *) arg;
    log_conn(self->m_log, trace, self, "{}", __func__);
    DnsFramedConnectionPtr ptr = self->shared_from_this();

    if (std::unique_lock l(self->m_mutex); self->m_closed) {
        log_conn(self->m_log, trace, self, "Already closed");
        return;
    }

    self->m_pool->add_connected(ptr);
    self->m_connected = true;
    if (self->m_idle_timeout.count()) {
        self->m_stream->set_timeout(self->m_idle_timeout);
    }
    self->m_cond.notify_all();
    log_conn(self->m_log, trace, self, "{} finished", __func__);
}

void DnsFramedConnection::on_read(void *arg, Uint8View data) {
    auto *self = (DnsFramedConnection *) arg;
    log_conn(self->m_log, trace, self, "{}", __func__);
    DnsFramedConnectionPtr ptr = self->shared_from_this();

    if (std::unique_lock l(self->m_mutex); self->m_closed) {
        log_conn(self->m_log, trace, self, "Already closed");
        return;
    }

    while (!data.empty()) {
        data = self->m_input_buffer.store(data);

        std::optional<Uint8Vector> packet = self->m_input_buffer.extract_packet();
        if (!packet.has_value()) {
            return;
        }

        int id = ntohs(*(uint16_t *) packet->data());
        log_conn(self->m_log, trace, self, "Got response for {}", id);

        std::unique_lock l(self->m_mutex);
        auto found = self->m_requests.find(id);
        if (found != self->m_requests.end()) {
            found->second = {std::move(packet.value())};
        }
        self->m_cond.notify_all();
    }

    log_conn(self->m_log, trace, self, "{} finished", __func__);
}

void DnsFramedConnection::on_close(void *arg, std::optional<Socket::Error> error) {
    auto *self = (DnsFramedConnection *) arg;
    log_conn(self->m_log, trace, self, "{}", __func__);
    DnsFramedConnectionPtr ptr = self->shared_from_this();

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
            result = {{}, {error.has_value() ? std::move(error->description) : std::string(UNEXPECTED_EOF)}};
        }
    }
    self->m_cond.notify_all();

    log_conn(self->m_log, trace, self, "{} finished", __func__);
}

Connection::ReadResult DnsFramedConnection::read(int request_id, Millis timeout) {
    DnsFramedConnectionPtr ptr = shared_from_this();
    std::unique_lock l(m_mutex);

    if (m_closed) {
        std::string msg = AG_FMT("{}: connection already closed", __func__);
        log_conn(m_log, trace, this, "{}", msg);
        return {{}, msg};
    }

    ++m_pending_requests_count;
    utils::ScopeExit request_unregister([this]() {
        std::scoped_lock lock(m_mutex);
        if (0 == --m_pending_requests_count) {
            m_no_requests_cond.notify_one();
        }
    });

    bool request_replied = m_cond.wait_until(l, steady_clock::now() + timeout, [&] {
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

void DnsFramedPool::add_connected(const ConnectionPtr &ptr) {
    DnsFramedConnection *conn = (DnsFramedConnection *) ptr.get();
    log_conn(conn->m_log, trace, conn, "{}", __func__);

    std::scoped_lock l(m_mutex);
    m_pending_connections.erase(ptr);
    m_connections.push_back(ptr);
}

void DnsFramedPool::remove_from_all(const ConnectionPtr &ptr) {
    DnsFramedConnection *conn = (DnsFramedConnection *) ptr.get();
    log_conn(conn->m_log, trace, conn, "{}", __func__);

    std::scoped_lock l(m_mutex);
    m_pending_connections.erase(ptr);
    m_connections.remove(ptr);

    if (!conn->m_closed) {
        close_connection(ptr);
    }
}

void DnsFramedPool::add_pending_connection(const ConnectionPtr &ptr) {
    DnsFramedConnection *conn = (DnsFramedConnection *) ptr.get();
    log_conn(conn->m_log, trace, conn, "{}", __func__);

    m_pending_connections.insert(ptr);
}

ConnectionPtr DnsFramedPool::create_connection(const SocketAddress &address,
        std::optional<SocketFactory::SecureSocketParameters> secure_socket_parameters, Millis idle_timeout) {
    static std::atomic_uint32_t conn_id{0};
    auto ptr = std::make_shared<DnsFramedConnection>(
            this, conn_id++, m_upstream, address, std::move(secure_socket_parameters), idle_timeout);
    ptr->start(m_upstream->options().timeout);
    return ptr;
}

// A connection should be deleted on the event loop, but some events may raise on already
// scheduled to delete one. That means that we should increment the reference counter until
// delete event is called.
void DnsFramedPool::close_connection(const ConnectionPtr &conn) {
    auto *framed_conn = (DnsFramedConnection *) conn.get();

    {
        std::scoped_lock l(framed_conn->m_mutex);

        framed_conn->m_closed = true;
        for (auto &[_, result] : framed_conn->m_requests) {
            // do not assign error, if we already got response
            if (!result.has_value()) {
                result = {{}, {"Connection has been forcibly closed"}};
            }
        }

        [[maybe_unused]] auto err = framed_conn->m_stream->set_callbacks({});
    }
    framed_conn->m_cond.notify_all();

    assert(!m_mutex.try_lock());
    m_closing_connections.emplace(conn);
    m_loop->submit([this, c = conn]() {
        std::scoped_lock l(m_mutex);
        m_closing_connections.erase(c);
        if (m_closing_connections.empty()) {
            m_no_conns_cond.notify_one();
        }
    });
}

DnsFramedPool::DnsFramedPool(EventLoopPtr loop, Upstream *upstream)
        : m_loop(std::move(loop))
        , m_upstream(upstream)
        , m_log(__func__) {
}

DnsFramedPool::~DnsFramedPool() {
    dbglog(m_log, "Destroying...");

    std::unique_lock l(m_mutex);

    for (const ConnectionPtr &conn : m_connections) {
        close_connection(conn);
    }
    m_connections.clear();
    for (const ConnectionPtr &conn : m_pending_connections) {
        close_connection(conn);
    }
    m_pending_connections.clear();

    dbglog(m_log, "Waiting until all connections are closed...");
    m_no_conns_cond.wait(l, [this]() -> bool {
        return m_connections.empty() && m_pending_connections.empty() && m_closing_connections.empty();
    });
    m_loop.reset();

    dbglog(m_log, "Destroyed");
}

Connection::ReadResult DnsFramedPool::perform_request_inner(Uint8View buf, Millis timeout) {
    auto [conn, elapsed, err] = get();
    if (!conn) {
        return {{}, std::move(err)};
    }

    if (buf.size() < 2) {
        return {{}, "Too short request"};
    }

    timeout -= duration_cast<Millis>(elapsed);
    if (timeout <= Millis(0)) {
        return {{}, AG_FMT("DNS server name resolving took too much time: {}", elapsed)};
    }

    utils::Timer timer;

    uint16_t id = ntohs(*(uint16_t *) buf.data());
    if (ErrString e = conn->wait_connect_result(id, timeout); e.has_value()) {
        return {{}, std::move(e)};
    }

    timeout -= timer.elapsed<decltype(timeout)>();
    if (timeout.count() <= 0) {
        return {{}, AG_FMT("Connect to DNS server took too much time: {}", timer.elapsed<decltype(timeout)>())};
    }

    if (ErrString e = conn->write(id, buf); e.has_value()) {
        return {{}, std::move(e)};
    }

    return conn->read(id, timeout);
}

Connection::ReadResult DnsFramedPool::perform_request(Uint8View buf, Millis timeout) {
    utils::Timer timer;
    Connection::ReadResult result = perform_request_inner(buf, timeout);
    // try one more time in case of the server closed the connection before we got the response
    // https://github.com/AdguardTeam/DnsLibs/issues/24
    if (result.error.has_value() && result.error.value() == DnsFramedConnection::UNEXPECTED_EOF) {
        timeout -= timer.elapsed<Millis>();
        if (timeout < Millis(0)) {
            result.error.emplace(TIMEOUT_STR.data());
        } else {
            result = perform_request_inner(buf, timeout);
        }
    }
    return result;
}

} // namespace ag
