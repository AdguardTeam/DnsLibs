#pragma once

#include <thread>
#include <memory> // for std::shared_ptr, std::unique_ptr
#include <list>
#include <map>
#include <mutex>
#include <condition_variable>
#include <utility>
#include <event2/event.h>
#include <event2/bufferevent.h>
#include <event2/thread.h>
#include <socket_address.h>
#include <upstream_util.h>
#include <ag_defs.h>
#include <ag_logger.h>
#include "event_loop.h"
#include "connection.h"

using event_base_ptr = std::shared_ptr<event_base>;
using bufferevent_ptr = std::shared_ptr<bufferevent>;

namespace ag {

class dns_framed_pool;

class dns_framed_connection;

using dns_framed_connection_ptr = std::shared_ptr<dns_framed_connection>;

class dns_framed_connection : public connection,
                              public std::enable_shared_from_this<dns_framed_connection> {
public:
    static dns_framed_connection_ptr create(dns_framed_pool *pool, bufferevent *bev, const socket_address &address);

    ~dns_framed_connection() override;

    int write(uint8_view_t buf) override;

    result read(int request_id, std::chrono::milliseconds timeout) override;

    const socket_address &address() const;


private:
    logger m_log;
    /** Connection pool */
    dns_framed_pool *m_pool;
    /** Connection handle */
    bufferevent *m_bev;
    /** Mutex for syncronizing reads and access */
    std::mutex m_mutex;
    /** Conditional variable for waiting reads */
    std::condition_variable m_cond;
    /** Map of requests to their results */
    ag::hash_map<int, std::optional<result>> m_requests;
    /** Connection remote address */
    socket_address m_socket_address;

    explicit dns_framed_connection(dns_framed_pool *pool, bufferevent *bev, const socket_address &address);

    void on_read();

    void on_event(int what);
};

class dns_framed_pool {
public:
    explicit dns_framed_pool(event_loop_ptr loop) : m_loop(std::move(loop)) {
    }

    ~dns_framed_pool() = default;

    // Copy is prohibited
    dns_framed_pool(const dns_framed_pool &) = delete;
    dns_framed_pool &operator=(const dns_framed_pool &) = delete;
    dns_framed_pool(dns_framed_pool &&) = delete;
    dns_framed_pool &operator=(dns_framed_pool &&) = delete;

    friend class dns_framed_connection;

protected:
    /** Event loop */
    event_loop_ptr m_loop;
    /** Connected connections. They may receive requests */
    ag::hash_map<socket_address, connection_ptr> m_connections;
    /** Pending connections. They may not receive requests yet */
    ag::hash_set<connection_ptr> m_pending_connections;

    void add_pending_connection(const dns_framed_connection_ptr &ptr);

    void add_connected(const dns_framed_connection_ptr &ptr);

    void remove_from_all(const dns_framed_connection_ptr &ptr);
};

class tcp_pool : public dns_framed_pool {
public:
    explicit tcp_pool(event_loop_ptr loop) : dns_framed_pool(std::move(loop)) {
    }
    virtual connection_ptr get_connection_to(const socket_address &dst) {
        int options = BEV_OPT_THREADSAFE | BEV_OPT_DEFER_CALLBACKS | BEV_OPT_UNLOCK_CALLBACKS;
        bufferevent *bev = bufferevent_socket_new(m_loop->c_base(), -1, options);
        dns_framed_connection_ptr connection = ag::dns_framed_connection::create(this, bev, dst);
        int r = bufferevent_socket_connect(bev, dst.c_sockaddr(), dst.c_socklen());
        add_pending_connection(connection);
        return connection;
    }
};

} // namespace ag
