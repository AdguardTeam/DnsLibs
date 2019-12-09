#pragma once

#include <string>
#include <vector>
#include <ag_logger.h>
#include <dnsfilter.h>
#include <upstream.h>
#include <dnsproxy_events.h>
#include <magic_enum.hpp>

namespace ag {

struct dns64_settings {
    upstream::options upstream_settings; // The upstream to use for discovery of DNS64 prefixes
    uint32_t max_tries; // How many times, at most, to try DNS64 prefixes discovery before giving up
    std::chrono::milliseconds wait_time; // How long to wait before a dns64 prefixes discovery attempt
};

enum class listener_protocol : int {
    UDP, TCP
};

struct listener_settings {
    std::string address{"::1"}; // The address to listen on
    uint16_t port{53}; // The port to listen on
    listener_protocol protocol{listener_protocol::UDP}; // The protocol to listen for
    bool persistent{false}; // Don't close the TCP connection after sending the first response
    std::chrono::milliseconds idle_timeout{3000}; // Close the TCP connection this long after the last request received

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

    std::vector<upstream::options> upstreams; // DNS upstreams settings list

    std::optional<dns64_settings> dns64; // DNS64 settings

    uint32_t blocked_response_ttl; // TTL of the record for the blocked domains (in seconds)

    dnsfilter::engine_params filter_params; // a filtering engine parameters (see `dnsfilter::engine_params`)

    std::vector<listener_settings> listeners; // List of addresses/ports/protocols/etc... to listen on
};

}
