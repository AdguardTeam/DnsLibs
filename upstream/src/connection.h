#pragma once

#include <ag_defs.h>
#include <socket_address.h>
#include <memory>
#include <vector>
#include <chrono>

namespace ag {

class connection;

using connection_ptr = std::shared_ptr<connection>;

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
    virtual int write(uint8_view_t buf) = 0;

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

} // namespace ag
