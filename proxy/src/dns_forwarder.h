#pragma once


#include <ag_logger.h>
#include <dnsproxy_settings.h>
#include <dnsproxy_events.h>
#include <dnsfilter.h>
#include <dns64.h>
#include <upstream.h>


namespace ag {

class dns_forwarder {
public:
    dns_forwarder();
    ~dns_forwarder();

    bool init(const dnsproxy_settings &settings);
    void deinit();

    using result = std::pair<std::vector<uint8_t>, err_string>;

    result handle_message(uint8_view message, dns_request_processed_event &event);

private:
    ldns_pkt_ptr try_dns64_aaaa_synthesis(upstream_ptr &upstream, const ldns_pkt_ptr &request,
        const ldns_pkt_ptr &response) const;

    void finalize_processed_event(dns_request_processed_event &event,
        const ldns_pkt *request, const ldns_pkt *response,
        const std::vector<const dnsfilter::rule *> &rules) const;

    logger log;
    const dnsproxy_settings *settings = nullptr;
    std::vector<upstream_ptr> upstreams;
    dnsfilter filter;
    dnsfilter::handle filter_handle = nullptr;
    dns64::prefixes dns64_prefixes;
};

}
