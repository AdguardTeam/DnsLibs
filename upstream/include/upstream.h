#ifndef AGDNS_UPSTREAM_UPSTREAM_H
#define AGDNS_UPSTREAM_UPSTREAM_H

#include <string>
#include <memory>
#include <ldns/packet.h>
#include <list>
#include <chrono>
#include <vector>
#include "upstream_util.h"

namespace ag {

class upstream;

using upstream_ptr = std::shared_ptr<upstream>;

/**
 * Upstream is interface for handling DNS requests to upstream servers
 */
class upstream {
public:

    /**
     * Options for upstream
     */
    struct options {
        /** List of plain DNS servers to be used to resolve DOH/DOT hostnames (if any) */
        std::list<std::string> bootstrap;

        /**
         * Default upstream timeout. Also, it is used as a timeout for bootstrap DNS requests.
         * timeout = 0 means infinite timeout.
         */
        std::chrono::milliseconds timeout;

        /** Resolver's IP address. In the case if it's specified, bootstrap DNS servers won't be used at all. */
        std::vector<uint8_t> server_ip;
    };

    /**
     * Convert the specified address to an upstream instance
     * @param address   8.8.8.8:53 -- plain DNS
     *                  tcp://8.8.8.8:53 -- plain DNS over TCP
     *                  tls://1.1.1.1 -- DNS-over-TLS
     *                  https://dns.adguard.com/dns-query -- DNS-over-HTTPS
     *                  sdns://... -- DNS stamp (see https://dnscrypt.info/stamps-specifications)
     * @param opts      Options for upstream creation
     * @return
     */
    static std::pair<upstream_ptr, err_string> address_to_upstream(std::string_view address, upstream::options &opts);

    virtual ~upstream() = default;

    /**
     * Do DNS request
     * @return Packet or an error
     */
    virtual std::pair<ldns_pkt *, err_string> exchange(ldns_pkt *) = 0;

    /**
     * Receive DNS server address
     * @return DNS server address
     */
    virtual std::string address() = 0;
};

} // namespace ag

#endif // AGDNS_UPSTREAM_UPSTREAM_H