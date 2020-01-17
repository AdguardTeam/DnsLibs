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
struct cache_key {
    std::string domain; // should be all lower-case for case-insensitivity
    bool do_bit;
    bool cd_bit;
    ldns_rr_type qtype;
    ldns_rr_class qclass;

    bool operator==(const cache_key &rhs) const;
    bool operator!=(const cache_key &rhs) const;
};
} // namespace ag

namespace std {
template<>
struct hash<ag::cache_key> {
    size_t operator()(const ag::cache_key &key) const;
};
} // namespace std

namespace ag {

struct cached_response {
    ldns_pkt_ptr response;
    ag::steady_clock::time_point expires_at;
};

class dns_forwarder {
public:
    dns_forwarder();
    ~dns_forwarder();

    bool init(const dnsproxy_settings &settings, const dnsproxy_events &events);
    void deinit();

    std::vector<uint8_t> handle_message(uint8_view message);

private:
    ldns_pkt_ptr create_response_from_cache(const cache_key &key, const ldns_pkt *request);
    void put_response_to_cache(cache_key key, ldns_pkt_ptr response);

    std::optional<uint8_vector> apply_filter(std::string_view hostname, const ldns_pkt *request,
        const ldns_pkt *original_response, dns_request_processed_event &event);

    ldns_pkt_ptr try_dns64_aaaa_synthesis(upstream *upstream, const ldns_pkt_ptr &request,
        const ldns_pkt_ptr &response) const;

    void finalize_processed_event(dns_request_processed_event &event,
        const ldns_pkt *request, const ldns_pkt *response, const ldns_pkt *original_response,
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

    with_mtx<lru_cache<cache_key, cached_response>, std::shared_mutex> response_cache;
};

} // namespace ag
