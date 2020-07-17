#pragma once


#include <ag_logger.h>
#include <ag_utils.h>
#include <ag_cache.h>
#include <ag_clock.h>
#include <dnsproxy_settings.h>
#include <dnsproxy_events.h>
#include <dnsfilter.h>
#include <dns64.h>
#include <upstream.h>
#include <certificate_verifier.h>
#include <shared_mutex>

namespace ag {

struct cached_response {
    ldns_pkt_ptr response;
    ag::steady_clock::time_point expires_at;
    std::optional<int32_t> upstream_id;
};

using cached_result = std::pair<ldns_pkt_ptr, std::optional<int32_t>>;

namespace dns_forwarder_utils {
/**
* Format RR list using the following format:
* <Type>, <RDFs, space separated>\n
* e.g.:
* A, 1.2.3.4
* AAAA, 12::34
* CNAME, google.com.
*/
std::string rr_list_to_string(const ldns_rr_list *rr_list);
} // namespace dns_forwarder_utils

class dns_forwarder {
public:
    dns_forwarder();
    ~dns_forwarder();

    std::pair<bool, err_string> init(const dnsproxy_settings &settings, const dnsproxy_events &events);
    void deinit();

    std::vector<uint8_t> handle_message(uint8_view message);

private:
    cached_result create_response_from_cache(const std::string &key, const ldns_pkt *request);
    void put_response_to_cache(std::string key, ldns_pkt_ptr response, std::optional<int32_t> upstream_id);

    std::optional<uint8_vector> apply_filter(std::string_view hostname,
                                             const ldns_pkt *request,
                                             const ldns_pkt *original_response,
                                             dns_request_processed_event &event,
                                             std::vector<dnsfilter::rule> &last_effective_rules,
                                             bool fire_event = true, ldns_pkt_rcode *out_rcode = nullptr);

    std::optional<uint8_vector> apply_cname_filter(const ldns_rr *cname_rr, const ldns_pkt *request,
                                                   const ldns_pkt *response, dns_request_processed_event &event,
                                                   std::vector<dnsfilter::rule> &last_effective_rules);

    std::optional<uint8_vector> apply_ip_filter(const ldns_rr *rr, const ldns_pkt *request,
                                                const ldns_pkt *response, dns_request_processed_event &event,
                                                std::vector<dnsfilter::rule> &last_effective_rules);

    ldns_pkt_ptr try_dns64_aaaa_synthesis(upstream *upstream, const ldns_pkt_ptr &request) const;

    void finalize_processed_event(dns_request_processed_event &event,
        const ldns_pkt *request, const ldns_pkt *response, const ldns_pkt *original_response,
        std::optional<int32_t> upstream_id, err_string error) const;

    logger log;
    const dnsproxy_settings *settings = nullptr;
    const dnsproxy_events *events = nullptr;
    std::vector<upstream_ptr> upstreams;
    std::vector<upstream_ptr> fallbacks;
    dnsfilter filter;
    dnsfilter::handle filter_handle = nullptr;
    dns64::prefixes dns64_prefixes;
    std::shared_ptr<certificate_verifier> cert_verifier;

    with_mtx<lru_cache<std::string, cached_response>, std::shared_mutex> response_cache;
};

} // namespace ag
