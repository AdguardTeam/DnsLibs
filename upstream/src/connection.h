#pragma once

#include "common/defs.h"
#include "common/socket_address.h"
#include <memory>
#include <vector>
#include <chrono>

namespace ag {

class connection;

using connection_ptr = std::shared_ptr<connection>;

/**
 * Abstract class for connections to various DNS upstream types
 */
class connection {
public:
    struct read_result {
        std::vector<uint8_t> reply; // Reply data
        ErrString error; // Some string in case of error
    };

    connection(const SocketAddress &addr) : address(addr) {}

    virtual ~connection() = default;

    /**
     * Wait for connect result
     * @param id connection id
     * @param timeout time out value
     * @return none if successful
     */
    virtual ErrString wait_connect_result(int request_id, std::chrono::milliseconds timeout) = 0;

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
    virtual read_result read(int request_id, std::chrono::milliseconds timeout) = 0;

    // Copy is prohibited
    connection(const connection &) = delete;
    connection &operator=(const connection &) = delete;

    const SocketAddress address;
};

/**
 * Abstract class for connection pool
 */
class connection_pool {
public:
    connection_pool() = default;
    virtual ~connection_pool() = default;
    struct get_result {
        connection_ptr conn; /**< Connection or null if error occurred */
        std::chrono::microseconds time_elapsed; /**< Elapsed time. Used for precise total timeout */
        ag::ErrString error;
    };
    /**
     * Get connection from pool
     */
    virtual get_result get() = 0;

    // Copy is prohibited
    connection_pool(const connection_pool &) = delete;
    connection_pool &operator=(const connection_pool &) = delete;
};

} // namespace ag
