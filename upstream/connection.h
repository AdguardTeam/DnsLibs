#pragma once

#include "common/defs.h"
#include "common/socket_address.h"
#include <memory>
#include <vector>
#include <chrono>

namespace ag {

class Connection;

using ConnectionPtr = std::shared_ptr<Connection>;

/**
 * Abstract class for connections to various DNS upstream types
 */
class Connection {
public:
    struct ReadResult {
        Uint8Vector reply; // Reply data
        ErrString error; // Some string in case of error
    };

    Connection(const SocketAddress &addr) : address(addr) {}

    virtual ~Connection() = default;

    /**
     * Wait for connect result
     * @param id connection id
     * @param timeout time out value
     * @return none if successful
     */
    virtual ErrString wait_connect_result(int request_id, Millis timeout) = 0;

    /**
     * Writes given DNS packet to framed connection
     * @param v DNS packet
     * @return none if successful
     */
    virtual ErrString write(int request_id, Uint8View buf) = 0;

    /**
     * Reads given DNS packet for given request id from framed connection
     * @param request_id request id to wait
     * @return see `read_result`
     */
    virtual ReadResult read(int request_id, Millis timeout) = 0;

    // Copy is prohibited
    Connection(const Connection &) = delete;
    Connection &operator=(const Connection &) = delete;

    const SocketAddress address;
};

/**
 * Abstract class for connection pool
 */
class ConnectionPool {
public:
    ConnectionPool() = default;
    virtual ~ConnectionPool() = default;
    struct GetResult {
        ConnectionPtr conn; /**< Connection or null if error occurred */
        Micros time_elapsed; /**< Elapsed time. Used for precise total timeout */
        ErrString error;
    };
    /**
     * Get connection from pool
     */
    virtual GetResult get() = 0;

    // Copy is prohibited
    ConnectionPool(const ConnectionPool &) = delete;
    ConnectionPool &operator=(const ConnectionPool &) = delete;
};

} // namespace ag
