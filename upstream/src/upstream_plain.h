#ifndef AGDNS_UPSTREAM_UPSTREAM_PLAIN_H
#define AGDNS_UPSTREAM_UPSTREAM_PLAIN_H

#include <utility>
#include <upstream.h>
#include <event2/event.h>
#include <ldns/net.h>
#include "connection_pool.h"

namespace ag {

/**
 * Plain DNS upstream
 */
class plain_dns : public ag::upstream {
public:
    /**
     * Create plain DNS upstream
     * @param address Server address. If port is not specified, default servce port will be used
     * @param timeout Timeout in milliseconds resolution
     * @param prefer_tcp If true, query will always be sent via TCP, otherwise it will be sent via tcp
     *                   only if contains `truncated` flag.
     */
    plain_dns(std::string_view address, const std::chrono::milliseconds &timeout, bool prefer_tcp);

    ~plain_dns() override = default;

    std::string address() override;

    std::pair<ldns_pkt *, err_string> exchange(ldns_pkt *request_pkt) override;

private:
    /** TCP connection pool */
    tcp_connection_pool m_pool;
    /** DNS server socket address */
    socket_address m_socket_address;
    /** Timeout */
    std::chrono::milliseconds m_timeout;
    /** Prefer TCP */
    bool m_prefer_tcp;
};

} // namespace ag

#endif //AGDNS_UPSTREAM_UPSTREAM_PLAIN_H
