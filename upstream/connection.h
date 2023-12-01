#pragma once

#include <memory>
#include <utility>
#include <vector>
#include <chrono>
#include <random>

#include "common/coro.h"
#include "common/defs.h"
#include "common/error.h"
#include "common/socket_address.h"
#include "dns/common/dns_defs.h"
#include "dns/common/event_loop.h"
#include "dns/upstream/upstream.h"

namespace ag::dns {

class Connection;
class ConnectionPoolBase;

using ConnectionPtr = std::shared_ptr<Connection>;
using ConnectionPoolPtr = std::shared_ptr<ConnectionPoolBase>;

/**
 * Abstract class for connections to various DNS upstream types
 */
class Connection {
protected:
    struct ConstructorAccess {};
public:
    enum class Status {
        IDLE,
        PENDING,
        ACTIVE,
        CLOSED,
    };

    using Reply = Result<std::vector<uint8_t>, DnsError>;

    struct Request {
        uint16_t request_id;
        uint16_t original_request_id;
        Connection *parent;
        Millis timeout;
        std::optional<Reply> reply;
        bool completed = false;
        std::coroutine_handle<> caller;

        void complete() {
            completed = true;
            if (caller) {
                std::exchange(caller, nullptr).resume();
            }
        }

        ~Request() {
            if (!completed && !reply) {
                reply = make_error(DnsError::AE_SHUTTING_DOWN);
            }
            complete();
        }
    };

    Connection(const ConstructorAccess & /*unused*/, EventLoop &loop, const ConnectionPoolPtr &pool, const std::string &address_str)
            : m_loop(loop)
            , m_pool(pool)
            , m_address_str(address_str) {
    }

    virtual ~Connection() = default;

    /**
     * Perform request via connection
     * @param request_id  Request identifier. Supplied separately because it doesn't match ID of DNS packet
     * @param packet  DNS request
     * @param timeout  Request timeout
     * @param handler  DNS response handler
     */
    virtual coro::Task<Reply> perform_request(Uint8View packet, Millis timeout) = 0;

    // Copy is prohibited
    Connection(const Connection &) = delete;
    Connection &operator=(const Connection &) = delete;

    Status m_state = Status::IDLE;
protected:
    /** Event loop */
    EventLoop &m_loop;
    /** Pool */
    std::weak_ptr<ConnectionPoolBase> m_pool;
    /** Upstream address string cached */
    std::string m_address_str;
};

/**
 * Abstract class for connection pool
 */
class ConnectionPoolBase : public std::enable_shared_from_this<ConnectionPoolBase> {
public:
    ConnectionPoolBase(EventLoop &loop, const std::shared_ptr<Upstream> &ups, int max_connections)
            : m_log(__func__)
            , m_max_connections(max_connections)
            , m_loop(loop)
            , m_upstream(ups)
    {
        m_address_str = ups->options().address;
        tracelog(m_log, "{} Created", m_address_str);
    };
    virtual ~ConnectionPoolBase() {
        tracelog(m_log, "{} Destroyed", m_address_str);
    }

    /**
     * Get connection from pool
     */
    ConnectionPtr get() {
        auto it = std::find_if(m_connections.begin(), m_connections.end(), [](const ConnectionPtr &conn){
            return conn->m_state == Connection::Status::ACTIVE;
        });
        if (it != m_connections.end()) {
            return *it;
        } else if (m_connections.size() < m_max_connections) {
            return create();
        } else {
            // Select any pending
            static std::random_device rd;
            static std::mt19937 gen{rd()};
            std::uniform_int_distribution<> dis(0, m_connections.size() - 1);
            auto it2 = m_connections.begin();
            std::advance(it2, dis(gen));
            return *it2;
        }
    }

    coro::Task<Connection::Reply> perform_request(Uint8View packet, Millis timeout) {
        // Connection must not outlive the pool, don't keep an extra ref during the lifetime of the coroutine.
        Connection *conn = get().get();
        co_return co_await conn->perform_request(packet, timeout);
    }

    virtual ConnectionPtr create() = 0;

    const std::string &address_str() {
        return m_address_str;
    }

    Upstream *upstream() {
        return m_upstream.lock().get();
    }

    void remove_connection(const ConnectionPtr &conn) {
        if (auto it = std::find(m_connections.begin(), m_connections.end(), conn); it != m_connections.end()) {
            m_connections.erase(it);
        }
    }

    // Copy is prohibited
    ConnectionPoolBase(const ConnectionPoolBase &) = delete;
    ConnectionPoolBase &operator=(const ConnectionPoolBase &) = delete;

protected:
    /** Logger */
    Logger m_log;
    /** Maximum number of connections */
    size_t m_max_connections;
    /** Event loop */
    EventLoop &m_loop;
    /** Connected connections. They may receive requests */
    std::list<ConnectionPtr> m_connections;
    /** Parent upstream */
    std::weak_ptr<Upstream> m_upstream;
    /** Upstream address str */
    std::string m_address_str;
};

template <typename ConnectionClass>
class ConnectionPool : public ConnectionPoolBase {
public:
    ConnectionPool(EventLoop &loop, const std::shared_ptr<Upstream> &ups, int max_connections)
            : ConnectionPoolBase(loop, ups, max_connections) {}
    ConnectionPtr create() override {
        auto conn = ConnectionClass::create(m_loop, shared_from_this(), address_str());
        m_connections.push_back(conn);
        return conn;
    }
};

} // namespace ag::dns
