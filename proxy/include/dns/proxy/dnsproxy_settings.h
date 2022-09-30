#pragma once

#include <string>
#include <vector>
#include <magic_enum.hpp>

#include "common/logger.h"
#include "common/net_utils.h"
#include "dns/dnsfilter/dnsfilter.h"
#include "dns/net/outbound_proxy_settings.h"
#include "dns/upstream/upstream.h"

#include "dnsproxy_events.h"

namespace ag::dns {

struct Dns64Settings {
    std::vector<UpstreamOptions> upstreams; // The upstreams to use for discovery of DNS64 prefixes
    uint32_t max_tries; // How many times, at most, to try DNS64 prefixes discovery before giving up
    Millis wait_time; // How long to wait before a dns64 prefixes discovery attempt
};

/**
 * Specifies how to respond to blocked requests.
 *
 * A request is blocked if it matches a blocking AdBlock-style rule,
 * or a blocking hosts-style rule. A blocking hosts-style rule is
 * a hosts-style rule with a loopback or all-zeroes address.
 *
 * Requests matching a hosts-style rule with an address that is
 * neither loopback nor all-zeroes are always responded
 * with the address specified by the rule.
 */
enum class DnsProxyBlockingMode {
    /** Respond with REFUSED response code */
    REFUSED,
    /** Respond with NXDOMAIN response code */
    NXDOMAIN,
    /**
     * Respond with an address that is all-zeroes, or
     * a custom blocking address, if it is specified, or
     * an empty SOA response if request type is not A/AAAA.
     */
    ADDRESS,
};

struct ListenerSettings {
    std::string address; // The address to listen on
    uint16_t port = 0; // The port to listen on
    utils::TransportProtocol protocol = utils::TP_UDP; // The protocol to listen for
    bool persistent = false; // If true, don't close the TCP connection after sending the first response
    Millis idle_timeout{}; // Close the TCP connection this long after the last request received

    /// If not -1, listen on this file descriptor, which must already be bound.
    /// The ownership is not transferred (caller must close the fd).
    /// Ignored on Windows.
    evutil_socket_t fd = -1;

    std::string str() const {
        return fmt::format(
                "(protocol: {}, address: {}, port: {}, persistent: {}, idle_timeout: {} ms)",
                magic_enum::enum_name(protocol), address, port, persistent, idle_timeout.count());
    }
};

struct DnsProxySettings {
    /**
     * Get the default DNS proxy settings
     * @return default DNS proxy settings
     */
    static const DnsProxySettings &get_default();

    std::vector<UpstreamOptions> upstreams; // DNS upstreams settings list
    std::vector<UpstreamOptions> fallbacks; // Fallback DNS upstreams settings list

    /**
     * Requests for these domains will be forwarded directly to the fallback upstreams, if there are any.
     * A wildcard character, `*`, which stands for any number of characters, is allowed to appear multiple
     * times anywhere except at the end of the domain (which implies that a domain consisting only of
     * wildcard characters is invalid).
     */
    std::vector<std::string> fallback_domains;

    std::optional<Dns64Settings> dns64; // DNS64 settings

    uint32_t blocked_response_ttl_secs; // TTL of the record for the blocked domains (in seconds)

    DnsFilter::EngineParams filter_params; // Filtering engine parameters (see `dnsfilter::engine_params`)

    std::vector<ListenerSettings> listeners; // List of addresses/ports/protocols/etc... to listen on

    std::optional<OutboundProxySettings> outbound_proxy; // Outbound proxy settings

    bool block_ipv6; // Block AAAA requests

    bool ipv6_available; // If false, bootstrappers will fetch only A records

    DnsProxyBlockingMode adblock_rules_blocking_mode; // How to respond to requests blocked by AdBlock-style rules
    DnsProxyBlockingMode hosts_rules_blocking_mode; // How to respond to requests blocked by hosts-style rules

    std::string custom_blocking_ipv4; // Custom IPv4 address to return for filtered requests
    std::string custom_blocking_ipv6; // Custom IPv6 address to return for filtered requests

    size_t dns_cache_size; // Maximum number of cached responses

    /**
     * Enable optimistic cache mode.
     * Expired cache entries will be returned with a TTL of 1 second
     * while upstreams are queried in the background.
     */
    bool optimistic_cache;

    /**
     * Enable DNSSEC OK extension.
     * This options tells server that we want to receive DNSSEC records along with normal queries.
     * If they exist, request processed event will have DNSSEC flag on.
     * WARNING: may increase data usage and probability of TCP fallbacks.
     */
    bool enable_dnssec_ok;

    /**
     * If enabled, detect retransmitted requests and handle them using fallback upstreams only.
     */
    bool enable_retransmission_handling;

    /** Block Encrypted Client Hello by removing the "ech" parameter from SVCB/HTTPS records. */
    bool block_ech;

    /**
     * Enable route resolver on Apple platforms.
     * This is needed when DnsProxy is used inside network extension and needs to use routes of some VPN.
     * No-op on non-Apple platforms.
     */
    bool enable_route_resolver = true;
};

}  // namespace ag::dns
