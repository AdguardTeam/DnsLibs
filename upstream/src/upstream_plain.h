#pragma once

#include <utility>
#include <upstream.h>
#include <event2/event.h>
#include <ldns/net.h>
#include "dns_framed.h"

namespace ag {

/**
 * Pool of TCP connections
 */
class tcp_pool : public dns_framed_pool {
public:
    /**
     * Create pool of TCP connections
     * @param loop Event loop
     * @param address Destination socket address
     */
    tcp_pool(event_loop_ptr loop, const socket_address &address) : dns_framed_pool(std::move(loop)),
                                                                   m_address(address) {
    }

    get_result get() override;

private:
    /** Destination socket address */
    socket_address m_address;

    get_result create();
};

/**
 * Plain DNS upstream
 */
class plain_dns : public ag::upstream {
public:
    /**
     * Create plain DNS upstream
     * @param address Server address. If port is not specified, default service port will be used
     * @param timeout Timeout in milliseconds resolution
     * @param prefer_tcp If true, query will always be sent via TCP, otherwise it will be sent via tcp
     *                   only if contains `truncated` flag.
     */
    plain_dns(std::string_view address, const std::chrono::milliseconds &timeout, bool prefer_tcp);

    ~plain_dns() override = default;

    std::string address() override;

    std::pair<ldns_pkt_ptr, err_string> exchange(ldns_pkt *request_pkt) override;

private:
    /** TCP connection pool */
    tcp_pool m_pool;
    /** DNS server socket address */
    socket_address m_socket_address;
    /** Timeout */
    std::chrono::milliseconds m_timeout;
    /** Prefer TCP */
    bool m_prefer_tcp;
};

} // namespace ag
