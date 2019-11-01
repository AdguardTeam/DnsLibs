#pragma once

#include <string>
#include <vector>
#include <ag_logger.h>
#include <dnsfilter.h>
#include <upstream.h>

namespace ag {

struct dnsproxy_settings {
    static const dnsproxy_settings &get_default();

    struct upstream_settings {
        std::string dns_server;
        upstream::options options;
    };
    std::vector<upstream_settings> upstreams;

    uint32_t blocked_response_ttl;

    dnsfilter::engine_params filter_params;
};

}
