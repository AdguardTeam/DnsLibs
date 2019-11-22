#pragma once

#include <ag_defs.h>
#include <string>
#include <string_view>
#include <memory>
#include <ldns/packet.h>
#include <list>
#include <chrono>
#include <vector>
#include <variant>
#include "ag_net_utils.h"

namespace ag {

class upstream;

using upstream_ptr = std::shared_ptr<upstream>;
using ldns_pkt_ptr = std::unique_ptr<ldns_pkt, ag::ftor<&ldns_pkt_free>>;

/**
 * Upstream is interface for handling DNS requests to upstream servers
 */
class upstream {
public:
    using address_to_upstream_result = std::pair<upstream_ptr, err_string>;

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
        using address_container = std::variant<std::monostate, uint8_array<4>, uint8_array<16>>;
        address_container server_ip;
    };

    using exchange_result = std::pair<ldns_pkt_ptr, err_string>;

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
    static address_to_upstream_result address_to_upstream(std::string_view address, const upstream::options &opts = upstream::options{});

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
