#pragma once

#include <ag_logger.h>
#include <mutex>
#include <list>
#include <condition_variable>
#include <event2/event.h>
#include <event2/bufferevent.h>
#include <event_loop.h>
#include "connection.h"

using bufferevent_ptr = std::unique_ptr<bufferevent, ag::ftor<&bufferevent_free>>;

namespace ag {

class dns_framed_pool;

class dns_framed_connection;

using dns_framed_connection_ptr = std::shared_ptr<dns_framed_connection>;

/**
 * DNS framed connection class.
 * It uses format specified in DNS RFC for TCP connections:
 * - Header is 2 bytes - length of payload
 * - Payload is DNS packet content as sent by UDP
 */
class dns_framed_connection : public connection,
                              public std::enable_shared_from_this<dns_framed_connection> {
public:
    /**
     * Creates DNS framed connection from bufferevent.
     * @param pool DNS pool that creates this connection
     * @param bev Bufferevent
     * @param address Destination address
     * @return Newly created DNS framed connection
     */
    static dns_framed_connection_ptr create(dns_framed_pool *pool, bufferevent *bev, const socket_address &address);

    ~dns_framed_connection() override;

    int write(uint8_view buf) override;

    result read(int request_id, std::chrono::milliseconds timeout) override;

    /**
     * @return Destionation address of this connection
     */
    const socket_address &address() const;

private:
    /** Logger */
    logger m_log;
    /** Connection pool */
    dns_framed_pool *m_pool;
    /** Connection handle */
    bufferevent_ptr m_bev;
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

/**
 * Abstract pool of DNS framed connections
 */
class dns_framed_pool : public connection_pool {
public:
    /**
     * @param loop Event loop
     */
    explicit dns_framed_pool(event_loop_ptr loop) : m_loop(std::move(loop)) {
    }

    ~dns_framed_pool() override = default;

    // Copy is prohibited
    dns_framed_pool(const dns_framed_pool &) = delete;
    dns_framed_pool &operator=(const dns_framed_pool &) = delete;

    friend class dns_framed_connection;

protected:
    /** Event loop */
    event_loop_ptr m_loop;
    /** Connected connections. They may receive requests */
    std::list<connection_ptr> m_connections;
    /** Pending connections. They may not receive requests yet */
    ag::hash_set<connection_ptr> m_pending_connections;

    void add_pending_connection(const dns_framed_connection_ptr &ptr);

    void add_connected(const dns_framed_connection_ptr &ptr);

    void remove_from_all(const dns_framed_connection_ptr &ptr);
};

} // namespace ag
