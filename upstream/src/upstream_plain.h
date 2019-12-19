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
    static constexpr std::string_view TCP_SCHEME = "tcp://";
    static constexpr int DEFAULT_PORT = 53;

    /**
     * Create plain DNS upstream
     * @param opts Upstream settings
     */
    plain_dns(const upstream::options &opts, const upstream_factory_config &config);

    ~plain_dns() override = default;

private:
    err_string init() override;
    exchange_result exchange(ldns_pkt *request_pkt) override;

    /** Prefer TCP */
    bool m_prefer_tcp;
    /** DNS server socket address */
    socket_address m_socket_address;
    /** TCP connection pool */
    tcp_pool m_pool;
};

} // namespace ag
