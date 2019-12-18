#pragma once

#include <ag_defs.h>
#include <ag_socket_address.h>
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
        std::vector<uint8_t> reply;
        err_string error;
    };

    connection(const socket_address &addr) : address(addr) {}

    virtual ~connection() = default;

    /**
     * Writes given DNS packet to framed connection
     * @param v DNS packet
     * @return Request ID to wait
     */
    virtual int write(uint8_view buf) = 0;

    /**
     * Reads given DNS packet for given request id from framed connection
     * @param request_id
     * @return
     */
    virtual read_result read(int request_id, std::chrono::milliseconds timeout) = 0;

    // Copy is prohibited
    connection(const connection &) = delete;
    connection &operator=(const connection &) = delete;

    const socket_address address;
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
        ag::err_string error;
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
