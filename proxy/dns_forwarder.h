#pragma once

#include <memory>
#include <random>
#include <shared_mutex>

#include "common/cache.h"
#include "common/clock.h"
#include "common/error.h"
#include "common/logger.h"
#include "common/utils.h"
#include "dns/dnsfilter/dnsfilter.h"
#include "dns/proxy/dnsproxy.h"
#include "dns/proxy/dnsproxy_events.h"
#include "dns/proxy/dnsproxy_settings.h"
#include "dns/upstream/upstream.h"

#include "dns64.h"
#include "response_cache.h"
#include "retransmission_detector.h"

namespace ag::dns {

struct UpstreamExchangeResult {
    Result<ldns_pkt_ptr, DnsError> result;
    Upstream *upstream;
};

class DnsForwarder {
public:
    using InitResult = std::pair<bool, Error<DnsProxyInitError>>;

    DnsForwarder();
    ~DnsForwarder();

    InitResult init(EventLoopPtr loop, const DnsProxySettings &settings, const DnsProxyEvents &events);
    void deinit();

    coro::Task<Uint8Vector> handle_message(Uint8View message, const DnsMessageInfo *info);

private:
    void truncate_response(ldns_pkt *response, const ldns_pkt *request, const DnsMessageInfo *info);

    coro::Task<Uint8Vector> handle_message_internal(
            Uint8View message, const DnsMessageInfo *info, bool fallback_only, uint16_t pkt_id);

    coro::Task<UpstreamExchangeResult> do_upstreams_exchange(std::string_view normalized_domain,
            const ldns_pkt *request, bool force_fallback, const DnsMessageInfo *info = nullptr);

    coro::Task<UpstreamExchangeResult> do_upstream_exchange(
            Upstream *upstream, const ldns_pkt *request, const DnsMessageInfo *info, Millis error_rtt);

    coro::Task<UpstreamExchangeResult> do_upstream_exchange_shared(
            Upstream *upstream, std::shared_ptr<const ldns_pkt> request, const DnsMessageInfo *info, Millis error_rtt);

    coro::Task<UpstreamExchangeResult> do_parallel_exchange(const std::vector<Upstream *> &upstreams,
            const ldns_pkt *request, const DnsMessageInfo *info, Millis error_rtt, bool wait_all);

    bool apply_fallback_filter(std::string_view hostname, const ldns_pkt *request);

    coro::Task<std::optional<Uint8Vector>> apply_filter(DnsFilter::MatchParam match, const ldns_pkt *request,
            const ldns_pkt *original_response, DnsRequestProcessedEvent &event,
            std::vector<DnsFilter::Rule> &last_effective_rules, bool fallback_only, bool fire_event = true,
            ldns_pkt_rcode *out_rcode = nullptr);

    coro::Task<std::optional<Uint8Vector>> apply_cname_filter(const ldns_rr *cname_rr, const ldns_pkt *request,
            const ldns_pkt *response, DnsRequestProcessedEvent &event,
            std::vector<DnsFilter::Rule> &last_effective_rules, bool fallback_only);

    coro::Task<std::optional<Uint8Vector>> apply_ip_filter(const ldns_rr *rr, const ldns_pkt *request,
            const ldns_pkt *response, DnsRequestProcessedEvent &event,
            std::vector<DnsFilter::Rule> &last_effective_rules, bool fallback_only);

    coro::Task<ldns_pkt_ptr> try_dns64_aaaa_synthesis(Upstream *upstream, const ldns_pkt_ptr &request) const;

    void finalize_processed_event(DnsRequestProcessedEvent &event, const ldns_pkt *request, const ldns_pkt *response,
            const ldns_pkt *original_response, std::optional<int32_t> upstream_id, Error<DnsError> error) const;

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
    dns64::Prefixes m_dns64_prefixes;
    std::shared_ptr<SocketFactory> m_socket_factory;
    std::shared_ptr<bool> m_shutdown_guard;
    ResponseCache m_response_cache;
    RetransmissionDetector m_retransmission_detector;
    std::default_random_engine m_random_engine;

    coro::Task<void> optimistic_cache_background_resolve(ldns_pkt_ptr req, std::string normalized_domain);
};

} // namespace ag::dns
