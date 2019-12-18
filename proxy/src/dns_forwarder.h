#pragma once


#include <ag_logger.h>
#include <dnsproxy_settings.h>
#include <dnsproxy_events.h>
#include <dnsfilter.h>
#include <dns64.h>
#include <upstream.h>
#include <certificate_verifier.h>


namespace ag {

class dns_forwarder {
public:
    dns_forwarder();
    ~dns_forwarder();

    bool init(const dnsproxy_settings &settings, const dnsproxy_events &events);
    void deinit();

    std::vector<uint8_t> handle_message(uint8_view message);

private:
    ldns_pkt_ptr try_dns64_aaaa_synthesis(upstream *upstream, const ldns_pkt_ptr &request,
        const ldns_pkt_ptr &response) const;

    void finalize_processed_event(dns_request_processed_event &event,
        const ldns_pkt *request, const ldns_pkt *response,
        const upstream *upstream, err_string error) const;

    logger log;
    const dnsproxy_settings *settings = nullptr;
    const dnsproxy_events *events = nullptr;
    std::vector<upstream_ptr> upstreams;
    dnsfilter filter;
    dnsfilter::handle filter_handle = nullptr;
    dns64::prefixes dns64_prefixes;
    std::shared_ptr<certificate_verifier> cert_verifier;

    struct application_verifier;
};

}
