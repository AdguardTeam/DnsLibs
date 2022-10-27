#pragma once

#include <uv.h>
#include <shared_mutex>

#include "common/logger.h"
#include "common/utils.h"
#include "common/cache.h"
#include "common/clock.h"
#include "dns/dnsfilter/dnsfilter.h"
#include "dns/proxy/dnsproxy_settings.h"
#include "dns/proxy/dnsproxy_events.h"
#include "dns/proxy/dnsproxy.h"
#include "dns/upstream/upstream.h"

#include "dns64.h"
#include "retransmission_detector.h"
#include "response_cache.h"

namespace ag::dns {

struct UpstreamExchangeResult {
    Result<ldns_pkt_ptr, DnsError> result;
    Upstream *upstream;
};

class DnsForwarder {
public:
    DnsForwarder();
    ~DnsForwarder();

    std::pair<bool, ErrString> init(EventLoopPtr loop, const DnsProxySettings &settings, const DnsProxyEvents &events);
    void deinit();

    coro::Task<Uint8Vector> handle_message(Uint8View message, const DnsMessageInfo *info);

private:

    void truncate_response(ldns_pkt *response, const ldns_pkt *request, const DnsMessageInfo *info);

    coro::Task<Uint8Vector> handle_message_internal(Uint8View message, const DnsMessageInfo *info,
            bool fallback_only, uint16_t pkt_id);

    coro::Task<UpstreamExchangeResult> do_upstream_exchange(std::string_view normalized_domain, ldns_pkt *request,
            bool fallback_only, const DnsMessageInfo *info = nullptr);

    bool apply_fallback_filter(std::string_view hostname, const ldns_pkt *request);

    coro::Task<std::optional<Uint8Vector>> apply_filter(
            DnsFilter::MatchParam match,
            const ldns_pkt *request,
            const ldns_pkt *original_response,
            DnsRequestProcessedEvent &event,
            std::vector<DnsFilter::Rule> &last_effective_rules,
            bool fallback_only,
            bool fire_event = true,
            ldns_pkt_rcode *out_rcode = nullptr
    );

    coro::Task<std::optional<Uint8Vector>> apply_cname_filter(
            const ldns_rr *cname_rr, const ldns_pkt *request,
            const ldns_pkt *response, DnsRequestProcessedEvent &event,
            std::vector<DnsFilter::Rule> &last_effective_rules,
            bool fallback_only);

    coro::Task<std::optional<Uint8Vector>> apply_ip_filter(
            const ldns_rr *rr, const ldns_pkt *request,
            const ldns_pkt *response, DnsRequestProcessedEvent &event,
            std::vector<DnsFilter::Rule> &last_effective_rules,
            bool fallback_only);

    coro::Task<ldns_pkt_ptr> try_dns64_aaaa_synthesis(Upstream *upstream, const ldns_pkt_ptr &request) const;

    void finalize_processed_event(DnsRequestProcessedEvent &event,
                                  const ldns_pkt *request, const ldns_pkt *response, const ldns_pkt *original_response,
                                  std::optional<int32_t> upstream_id, ErrString error) const;

    bool do_dnssec_log_logic(ldns_pkt *request);
    bool finalize_dnssec_log_logic(ldns_pkt *response, bool is_our_do_bit);

    Logger m_log{"dns_forwarder"};
    EventLoopPtr m_loop;
    const DnsProxySettings *m_settings = nullptr;
    const DnsProxyEvents *m_events = nullptr;
    std::vector<UpstreamPtr> m_upstreams;
    std::vector<UpstreamPtr> m_fallbacks;
    DnsFilter m_filter;
    DnsFilter::Handle m_filter_handle = nullptr;
    DnsFilter::Handle m_fallback_filter_handle = nullptr;
    dns64::StatePtr m_dns64_state = nullptr;
    std::shared_ptr<SocketFactory> m_socket_factory;
    std::shared_ptr<bool> m_shutdown_guard;

    ResponseCache m_response_cache;

    RetransmissionDetector m_retransmission_detector;

    coro::Task<void> optimistic_cache_background_resolve(ldns_pkt_ptr req, std::string normalized_domain);
};

} // namespace ag::dns
