#pragma once

#include <uv.h>
#include <shared_mutex>

#include "common/logger.h"
#include "common/utils.h"
#include "common/cache.h"
#include "common/clock.h"
#include "dnsfilter/dnsfilter.h"
#include "proxy/dnsproxy_settings.h"
#include "proxy/dnsproxy_events.h"
#include "proxy/dnsproxy.h"
#include "upstream/upstream.h"

#include "dns64.h"
#include "retransmission_detector.h"

namespace ag {

struct CachedResponse {
    ldns_pkt_ptr response;
    SteadyClock::time_point expires_at;
    std::optional<int32_t> upstream_id;
};

struct CacheResult {
    ldns_pkt_ptr response;
    std::optional<int32_t> upstream_id;
    bool expired;
};

struct UpstreamExchangeResult {
    ldns_pkt_ptr response;
    ErrString error;
    Upstream *upstream;
};

namespace DnsForwarderUtils {
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

class DnsForwarder {
public:
    DnsForwarder();
    ~DnsForwarder();

    std::pair<bool, ErrString> init(const DnsProxySettings &settings, const DnsProxyEvents &events);
    void deinit();

    Uint8Vector handle_message(Uint8View message, const DnsMessageInfo *info);

private:
    static void async_request_worker(uv_work_t *);
    static void async_request_finalizer(uv_work_t *, int);

    void truncate_response(ldns_pkt *response, const ldns_pkt *request, const DnsMessageInfo *info);

    Uint8Vector handle_message_internal(Uint8View message, const DnsMessageInfo *info,
                                        bool fallback_only, uint16_t pkt_id);

    UpstreamExchangeResult do_upstream_exchange(std::string_view normalized_domain, ldns_pkt *request,
                                                bool fallback_only, const DnsMessageInfo *info = nullptr);

    CacheResult create_response_from_cache(const std::string &key, const ldns_pkt *request);

    void put_response_into_cache(std::string key, ldns_pkt_ptr response, std::optional<int32_t> upstream_id);

    bool apply_fallback_filter(std::string_view hostname, const ldns_pkt *request);

    std::optional<Uint8Vector> apply_filter(
            DnsFilter::MatchParam match,
            const ldns_pkt *request,
            const ldns_pkt *original_response,
            DnsRequestProcessedEvent &event,
            std::vector<DnsFilter::Rule> &last_effective_rules,
            bool fallback_only,
            bool fire_event = true,
            ldns_pkt_rcode *out_rcode = nullptr
    );

    std::optional<Uint8Vector> apply_cname_filter(const ldns_rr *cname_rr, const ldns_pkt *request,
                                                  const ldns_pkt *response, DnsRequestProcessedEvent &event,
                                                  std::vector<DnsFilter::Rule> &last_effective_rules,
                                                  bool fallback_only);

    std::optional<Uint8Vector> apply_ip_filter(const ldns_rr *rr, const ldns_pkt *request,
                                               const ldns_pkt *response, DnsRequestProcessedEvent &event,
                                               std::vector<DnsFilter::Rule> &last_effective_rules,
                                               bool fallback_only);

    ldns_pkt_ptr try_dns64_aaaa_synthesis(Upstream *upstream, const ldns_pkt_ptr &request) const;

    void finalize_processed_event(DnsRequestProcessedEvent &event,
                                  const ldns_pkt *request, const ldns_pkt *response, const ldns_pkt *original_response,
                                  std::optional<int32_t> upstream_id, ErrString error) const;

    bool do_dnssec_log_logic(ldns_pkt *request);
    bool finalize_dnssec_log_logic(ldns_pkt *response, bool is_our_do_bit);

    void remove_ech_svcparam(ldns_pkt *response);

    Logger m_log{"dns_forwarder"};
    const DnsProxySettings *m_settings = nullptr;
    const DnsProxyEvents *m_events = nullptr;
    std::vector<UpstreamPtr> m_upstreams;
    std::vector<UpstreamPtr> m_fallbacks;
    DnsFilter m_filter;
    DnsFilter::Handle m_filter_handle = nullptr;
    DnsFilter::Handle m_fallback_filter_handle = nullptr;
    dns64::Prefixes m_dns64_prefixes;
    std::shared_ptr<SocketFactory> m_socket_factory;

    WithMtx<LruCache<std::string, CachedResponse>, std::shared_mutex> m_response_cache;

    RetransmissionDetector m_retransmission_detector;

    struct AsyncRequest {
        uv_work_t work{};
        DnsForwarder *forwarder{};
        ldns_pkt_ptr request;
        std::string cache_key;
        std::string normalized_domain; // domain name without dot in the end

        AsyncRequest() {
            work.data = this;
        }
    };

    // Map of async requests in flight (cache key -> uv work handle)
    std::unordered_map<std::string, AsyncRequest> m_async_reqs;
    std::mutex m_async_reqs_mtx;
    std::condition_variable m_async_reqs_cv;
};

} // namespace ag
