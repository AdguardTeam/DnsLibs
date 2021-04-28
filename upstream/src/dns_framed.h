#pragma once

#include <ag_logger.h>
#include <upstream.h>
#include <mutex>
#include <list>
#include <condition_variable>
#include <event2/event.h>
#include <event2/bufferevent.h>
#include <ag_event_loop.h>
#include "connection.h"

namespace ag {

class dns_framed_connection;

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

    ~dns_framed_pool();

    // Copy is prohibited
    dns_framed_pool(const dns_framed_pool &) = delete;
    dns_framed_pool &operator=(const dns_framed_pool &) = delete;

    /**
     * Send given data to the server and get the response
     * @param buf request data
     * @param timeout operation timeout
     * @return Response in case of success, or an error in case of something went wrong
     */
    connection::read_result perform_request(uint8_view buf, std::chrono::milliseconds timeout);

protected:
    friend class dns_framed_connection;

    /** Event loop */
    event_loop_ptr m_loop;
    /** Mutex for connections */
    mutable std::mutex m_mutex;
    /** Connected connections. They may receive requests */
    std::list<connection_ptr> m_connections;
    /** Pending connections. They may not receive requests yet */
    hash_set<connection_ptr> m_pending_connections;
    /** Number of currently open (or not completely closed) connections */
    size_t m_active_connections_count = 0;
    /** Signals when all connections are closed */
    std::condition_variable_any m_no_conns_cond;

    void add_pending_connection(const connection_ptr &ptr);

    void add_connected(const connection_ptr &ptr);

    void remove_from_all(const connection_ptr &ptr);

    virtual connection::read_result perform_request_inner(uint8_view buf, std::chrono::milliseconds timeout);

    /**
     * Creates DNS framed connection from bufferevent.
     * @param bev Bufferevent
     * @param address Destination address
     * @return Newly created DNS framed connection
     */
    connection_ptr create_connection(bufferevent *bev, const socket_address &address);

    void close_connection(const connection_ptr &conn);
};

} // namespace ag
