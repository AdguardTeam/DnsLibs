#pragma once

#include <chrono>
#include <memory>
#include <string>
#include <string_view>
#include <vector>
#include <ldns/packet.h>
#include <ag_defs.h>
#include <ag_net_consts.h>
#include <ag_net_utils.h>

namespace ag {

class upstream;

using upstream_ptr = std::shared_ptr<upstream>;
using ldns_pkt_ptr = std::unique_ptr<ldns_pkt, ag::ftor<&ldns_pkt_free>>;

/**
 * Upstream is interface for handling DNS requests to upstream servers
 */
class upstream {
public:
    struct address_to_upstream_result {
        upstream_ptr upstream;
        err_string error;
    };

    struct exchange_result {
        ldns_pkt_ptr packet;
        err_string error;
    };

    /**
     * Options for upstream
     */
    struct options {
        /** List of plain DNS servers to be used to resolve DOH/DOT hostnames (if any) */
        std::vector<std::string> bootstrap;

        /**
         * Default upstream timeout. Also, it is used as a timeout for bootstrap DNS requests.
         * timeout = 0 means infinite timeout.
         */
        std::chrono::milliseconds timeout;

        /** Resolver's IP address. In the case if it's specified, bootstrap DNS servers won't be used at all. */
        ip_address_variant server_ip;
    };

    /**
     * Convert the specified address to an upstream instance
     * @param address   8.8.8.8:53 -- plain DNS
     *                  tcp://8.8.8.8:53 -- plain DNS over TCP
     *                  tls://1.1.1.1 -- DNS-over-TLS
     *                  https://dns.adguard.com/dns-query -- DNS-over-HTTPS
     *                  sdns://... -- DNS stamp (see https://dnscrypt.info/stamps-specifications)
     * @param opts      Options for upstream creation
     * @return Pointer to newly created upstream or error
     */
    static address_to_upstream_result address_to_upstream(std::string_view address, const options &opts = {});

    virtual ~upstream() = default;

    /**
     * Do DNS request
     * @param request DNS request packet
     * @return DNS response packet or an error
     */
    virtual exchange_result exchange(ldns_pkt *request) = 0;

    /**
     * Receive DNS server address
     * @return DNS server address
     */
    virtual std::string address() = 0;
};

} // namespace ag
