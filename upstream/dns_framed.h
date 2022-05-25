#pragma once

#include "common/logger.h"
#include "common/event_loop.h"
#include "upstream/upstream.h"
#include <mutex>
#include <list>
#include <condition_variable>
#include <event2/event.h>
#include <event2/bufferevent.h>
#include "common/event_loop.h"
#include "connection.h"
#include "net/tls_session_cache.h"

namespace ag {

class DnsFramedConnection;

/**
 * Abstract pool of DNS framed connections
 */
class DnsFramedPool : public ConnectionPool {
public:
    DnsFramedPool(EventLoopPtr loop, Upstream *upstream);
    ~DnsFramedPool() override;

    // Copy is prohibited
    DnsFramedPool(const DnsFramedPool &) = delete;
    DnsFramedPool &operator=(const DnsFramedPool &) = delete;

    /**
     * Send given data to the server and get the response
     * @param buf request data
     * @param timeout operation timeout
     * @return Response in case of success, or an error in case of something went wrong
     */
    Connection::ReadResult perform_request(Uint8View buf, Millis timeout);

protected:
    friend class DnsFramedConnection;

    /** Event loop */
    EventLoopPtr m_loop;
    /** Mutex for connections */
    mutable std::mutex m_mutex;
    /** Connected connections. They may receive requests */
    std::list<ConnectionPtr> m_connections;
    /** Pending connections. They may not receive requests yet */
    HashSet<ConnectionPtr> m_pending_connections;
    /** Parent upstream */
    Upstream *m_upstream = nullptr;
    /** The connections about to close. They may not receive requests and responses */
    HashSet<ConnectionPtr> m_closing_connections;
    /** Signals when all connections are closed */
    std::condition_variable_any m_no_conns_cond;
    /** Logger */
    Logger m_log;

    void add_pending_connection(const ConnectionPtr &ptr);

    void add_connected(const ConnectionPtr &ptr);

    void remove_from_all(const ConnectionPtr &ptr);

    virtual Connection::ReadResult perform_request_inner(Uint8View buf, Millis timeout);

    /**
     * Creates DNS framed connection from bufferevent.
     * @param address Destination address
     * @param secure_socket_parameters Non-nullopt in case it's a secured connection
     * @param idle_timeout Idle timeout. If 0, request timeout will be used.
     * @return Newly created DNS framed connection
     */
    ConnectionPtr create_connection(const SocketAddress &address,
                                    std::optional<SocketFactory::SecureSocketParameters> secure_socket_parameters,
                                    Millis idle_timeout = Millis{0});

    void close_connection(const ConnectionPtr &conn);
};

} // namespace ag
