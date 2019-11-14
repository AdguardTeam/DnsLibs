#pragma once

#include <string>
#include <vector>
#include <ag_logger.h>
#include <dnsfilter.h>
#include <upstream.h>
#include <dnsproxy_events.h>

namespace ag {

struct dnsproxy_settings {
    /**
     * @brief Get the default DNS proxy settings
     * @return default DNS proxy settings
     */
    static const dnsproxy_settings &get_default();

    struct upstream_settings {
        std::string dns_server; // a DNS server address
        upstream::options options; // a DNS upstream options (see `upstream::options`)
    };
    std::vector<upstream_settings> upstreams; // DNS upstreams settings list

    uint32_t blocked_response_ttl; // TTL of the record for the blocked domains (in seconds)

    dnsfilter::engine_params filter_params; // a filtering engine parameters (see `dnsfilter::engine_params`)
};

}
