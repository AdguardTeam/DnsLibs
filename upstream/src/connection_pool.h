#ifndef AGDNS_UPSTREAM_CONNECTION_POOL_H
#define AGDNS_UPSTREAM_CONNECTION_POOL_H

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
#include "event_loop.h"

using event_base_ptr = std::shared_ptr<event_base>;
using bufferevent_ptr = std::shared_ptr<bufferevent>;

namespace ag {

class connection;

class tcp_connection_pool;

class dns_framed_connection;

using connection_ptr = std::shared_ptr<connection>;
using dns_framed_connection_ptr = std::shared_ptr<dns_framed_connection>;

class connection {
public:
    using result = std::pair<std::vector<uint8_t>, err_string>;

    connection() = default;

    virtual ~connection() = default;

    /**
     * Writes given DNS packet to framed connection
     * @param v DNS packet
     * @return Request ID to wait
     */
    virtual int write(vector_view buf) = 0;

    /**
     * Reads given DNS packet for given request id from framed connection
     * @param request_id
     * @return
     */
    virtual result read(int request_id, std::chrono::milliseconds timeout) = 0;

    // Copy is prohibited
    connection(const connection &) = delete;
    connection &operator=(const connection &) = delete;
    connection(connection &&) = delete;
    connection &operator=(connection &&) = delete;
};

class dns_framed_connection : public connection,
                              public std::enable_shared_from_this<dns_framed_connection> {
public:
    static dns_framed_connection_ptr create(tcp_connection_pool *pool, bufferevent *bev, const socket_address &address);

    ~dns_framed_connection() override;

    int write(vector_view buf) override;

    result read(int request_id, std::chrono::milliseconds timeout) override;

    const socket_address &address() const;


private:
    /** Connection pool */
    tcp_connection_pool *m_pool;
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

    explicit dns_framed_connection(tcp_connection_pool *pool, bufferevent *bev, const socket_address &address);

    void on_read();

    void on_event(int what);
};

class tcp_connection_pool {
public:
    connection_ptr get_connection_to(const socket_address &dst) {
        int options = BEV_OPT_THREADSAFE | BEV_OPT_DEFER_CALLBACKS | BEV_OPT_UNLOCK_CALLBACKS;
        bufferevent *bev = bufferevent_socket_new(m_loop->c_base(), -1, options);
        connection_ptr connection = ag::dns_framed_connection::create(this, bev, dst);
        int r = bufferevent_socket_connect(bev, dst.c_sockaddr(), dst.c_socklen());
        m_pending_connections[connection] = dst;
        return connection;
    }

    explicit tcp_connection_pool(event_loop_ptr loop) : m_loop(std::move(loop)) {
    }

    ~tcp_connection_pool() = default;

    // Copy is prohibited
    tcp_connection_pool(const tcp_connection_pool &) = delete;
    tcp_connection_pool &operator=(const tcp_connection_pool &) = delete;
    tcp_connection_pool(tcp_connection_pool &&) = delete;
    tcp_connection_pool &operator=(tcp_connection_pool &&) = delete;

    friend class dns_framed_connection;

private:
    /** Event loop */
    event_loop_ptr m_loop;
    /** Connected connections. They may receive requests */
    ag::hash_map<socket_address, connection_ptr> m_connections;
    /** Pending connections. They may not receive requests yet */
    ag::hash_map<connection_ptr, socket_address> m_pending_connections;

    void add(const dns_framed_connection_ptr &ptr);

    void remove(const dns_framed_connection_ptr &ptr);
};

} // namespace ag

#endif //AGDNS_UPSTREAM_CONNECTION_POOL_H
