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
#include <certificate_verifier.h>

namespace ag {

class upstream;

using upstream_ptr = std::shared_ptr<upstream>;
using ldns_pkt_ptr = std::unique_ptr<ldns_pkt, ag::ftor<&ldns_pkt_free>>;

/**
 * Upstream is interface for handling DNS requests to upstream servers
 */
class upstream {
public:
    struct exchange_result {
        ldns_pkt_ptr packet;
        err_string error;
    };

    /**
     * Options for upstream
     */
    struct options {
        /**
         * Server address, one of the following kinds:
         *     8.8.8.8:53 -- plain DNS
         *     tcp://8.8.8.8:53 -- plain DNS over TCP
         *     tls://1.1.1.1 -- DNS-over-TLS
         *     https://dns.adguard.com/dns-query -- DNS-over-HTTPS
         *     sdns://... -- DNS stamp (see https://dnscrypt.info/stamps-specifications)
         */
        std::string address;

        /** List of plain DNS servers to be used to resolve DOH/DOT hostnames (if any) */
        std::vector<std::string> bootstrap;

        /**
         * Default upstream timeout. Also, it is used as a timeout for bootstrap DNS requests.
         * timeout = 0 means infinite timeout.
         */
        std::chrono::milliseconds timeout;

        /** Resolver's IP address. In the case if it's specified, bootstrap DNS servers won't be used at all. */
        ip_address_variant resolved_server_ip;
    };

    explicit upstream(const options &opts) : opts(opts) {}

    virtual ~upstream() = default;

    /**
     * Do DNS request
     * @param request DNS request packet
     * @return DNS response packet or an error
     */
    virtual exchange_result exchange(ldns_pkt *request) = 0;

    /** Upstream options */
    const upstream::options opts;
};

/**
 * Upstream factory entity which produces upstreams
 */
class upstream_factory {
public:
    /**
     * The factory configuration
     */
    struct config {
        const certificate_verifier *cert_verifier = nullptr;
    };

    struct create_result {
        upstream_ptr upstream; // created upstream in case of success
        err_string error; // non-nullopt in case of error
    };

    explicit upstream_factory(config cfg);
    ~upstream_factory();

    /**
     * Create an upstream
     * @param opts upstream settings
     * @return Creation result
     */
    create_result create_upstream(const upstream::options &opts) const;

    struct impl;
private:
    std::unique_ptr<impl> factory;
};

} // namespace ag
