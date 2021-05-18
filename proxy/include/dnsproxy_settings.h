#pragma once

#include <string>
#include <vector>
#include <ag_logger.h>
#include <dnsfilter.h>
#include <upstream.h>
#include <dnsproxy_events.h>
#include <magic_enum.hpp>
#include <ag_outbound_proxy_settings.h>

namespace ag {

struct dns64_settings {
    std::vector<upstream_options> upstreams; // The upstreams to use for discovery of DNS64 prefixes
    uint32_t max_tries; // How many times, at most, to try DNS64 prefixes discovery before giving up
    std::chrono::milliseconds wait_time; // How long to wait before a dns64 prefixes discovery attempt
};

enum class listener_protocol {
    UDP,
    TCP,
};

/**
 * Specifies how to respond to filtered requests
 */
enum class dnsproxy_blocking_mode {
    DEFAULT, // AdBlock-style filters -> REFUSED, hosts-style filters -> rule-specified or unspecified address
    REFUSED, // Always return REFUSED
    NXDOMAIN, // Always return NXDOMAIN
    UNSPECIFIED_ADDRESS, // Always return unspecified address
    CUSTOM_ADDRESS, // Always return custom configured IP address (see dnsproxy_settings)
};

struct listener_settings {
    std::string address{"::"}; // The address to listen on
    uint16_t port{53}; // The port to listen on
    listener_protocol protocol{listener_protocol::UDP}; // The protocol to listen for
    bool persistent{false}; // If true, don't close the TCP connection after sending the first response
    std::chrono::milliseconds idle_timeout{3000}; // Close the TCP connection this long after the last request received

    /// If not -1, listen on this file descriptor, which must already be bound.
    /// The ownership is not transferred (caller must close the fd).
    /// Ignored on Windows.
    evutil_socket_t fd{-1};

    std::string str() const {
        return fmt::format(
                "(protocol: {}, address: {}, port: {}, persistent: {}, idle_timeout: {} ms)",
                magic_enum::enum_name(protocol), address, port, persistent, idle_timeout.count());
    }
};

struct dnsproxy_settings {
    /**
     * Get the default DNS proxy settings
     * @return default DNS proxy settings
     */
    static const dnsproxy_settings &get_default();

    std::vector<upstream_options> upstreams; // DNS upstreams settings list
    std::vector<upstream_options> fallbacks; // Fallback DNS upstreams settings list

    /**
     * Enable handling dns suffixes.
     * If `true` then dnslibs will redirect requests with system dns suffixes
     * and user's dns suffixes only to fallbacks
     */
    bool handle_dns_suffixes = false;
    std::vector<std::string> dns_suffixes;

    std::optional<dns64_settings> dns64; // DNS64 settings

    uint32_t blocked_response_ttl_secs; // TTL of the record for the blocked domains (in seconds)

    dnsfilter::engine_params filter_params; // Filtering engine parameters (see `dnsfilter::engine_params`)

    std::vector<listener_settings> listeners; // List of addresses/ports/protocols/etc... to listen on

    std::optional<outbound_proxy_settings> outbound_proxy; // Outbound proxy settings

    bool block_ipv6; // Block AAAA requests

    bool ipv6_available; // If false, bootstrappers will fetch only A records

    dnsproxy_blocking_mode blocking_mode; // How to respond to filtered requests

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
};

}
