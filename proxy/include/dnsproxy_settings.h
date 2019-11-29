#pragma once

#include <string>
#include <vector>
#include <ag_logger.h>
#include <dnsfilter.h>
#include <upstream.h>
#include <dnsproxy_events.h>

namespace ag {

struct upstream_settings {
    std::string dns_server; // a DNS server address
    upstream::options options; // a DNS upstream options (see `upstream::options`)
};

struct dns64_settings {
    upstream_settings upstream; // The upstream to use for discovery of DNS64 prefixes
    uint32_t max_tries; // How many times, at most, to try DNS64 prefixes discovery before giving up
    std::chrono::milliseconds wait_time; // How long to wait before a dns64 prefixes discovery attempt
};

struct dnsproxy_settings {
    /**
     * @brief Get the default DNS proxy settings
     * @return default DNS proxy settings
     */
    static const dnsproxy_settings &get_default();

    std::vector<upstream_settings> upstreams; // DNS upstreams settings list

    std::optional<dns64_settings> dns64;

    uint32_t blocked_response_ttl; // TTL of the record for the blocked domains (in seconds)

    dnsfilter::engine_params filter_params; // a filtering engine parameters (see `dnsfilter::engine_params`)
};

}
