#pragma once

#include <ag_logger.h>
#include <ag_event_loop.h>
#include <upstream.h>
#include <mutex>
#include <list>
#include <condition_variable>
#include <event2/event.h>
#include <event2/bufferevent.h>
#include <ag_event_loop.h>
#include "connection.h"
#include <tls_session_cache.h>

namespace ag {

class dns_framed_connection;

/**
 * Abstract pool of DNS framed connections
 */
class dns_framed_pool : public connection_pool {
public:
    dns_framed_pool(event_loop_ptr loop, upstream *upstream);
    ~dns_framed_pool() override;

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
    /** Parent upstream */
    upstream *m_upstream = nullptr;
    /** The connections about to close. They may not receive requests and responses */
    hash_set<connection_ptr> m_closing_connections;
    /** Signals when all connections are closed */
    std::condition_variable_any m_no_conns_cond;
    /** Logger */
    logger m_log;

    void add_pending_connection(const connection_ptr &ptr);

    void add_connected(const connection_ptr &ptr);

    void remove_from_all(const connection_ptr &ptr);

    virtual connection::read_result perform_request_inner(uint8_view buf, std::chrono::milliseconds timeout);

    /**
     * Creates DNS framed connection from bufferevent.
     * @param address Destination address
     * @param secure_socket_parameters Non-nullopt in case it's a secured connection
     * @return Newly created DNS framed connection
     */
    connection_ptr create_connection(const socket_address &address,
            std::optional<socket_factory::secure_socket_parameters> secure_socket_parameters);

    void close_connection(const connection_ptr &conn);
};

} // namespace ag
