#include <algorithm>
#include <cassert>
#include <cstring>
#include <ldns/ldns.h>
#include <string>

#include "common/cache.h"
#include "common/error.h"
#include "common/parallel.h"
#include "common/utils.h"
#include "dns/net/application_verifier.h"
#include "dns/net/default_verifier.h"
#include "dns/proxy/dnsproxy.h"

#include "dns64.h"
#include "dns_forwarder.h"
#include "dns_forwarder_utils.h"
#include "dns_truncate.h"
#include "dnssec_ok.h"
#include "proxy_bootstrapper.h"
#include "response_cache.h"
#include "response_helpers.h"
#include "svcb.h"

#define errlog_id(l_, pkt_, fmt_, ...) errlog((l_), "[{}] " fmt_, ldns_pkt_id(pkt_), ##__VA_ARGS__)
#define errlog_fid(l_, pkt_, fmt_, ...) errlog((l_), "[{}] " fmt_, ldns_pkt_id(pkt_), ##__VA_ARGS__)
#define warnlog_id(l_, pkt_, fmt_, ...) warnlog((l_), "[{}] " fmt_, ldns_pkt_id(pkt_), ##__VA_ARGS__)
#define warnlog_fid(l_, pkt_, fmt_, ...) warnlog((l_), "[{}] " fmt_, ldns_pkt_id(pkt_), ##__VA_ARGS__)
#define dbglog_id(l_, pkt_, fmt_, ...) dbglog((l_), "[{}] " fmt_, ldns_pkt_id(pkt_), ##__VA_ARGS__)
#define dbglog_fid(l_, pkt_, fmt_, ...) dbglog((l_), "[{}] " fmt_, ldns_pkt_id(pkt_), ##__VA_ARGS__)
#define tracelog_id(l_, pkt_, fmt_, ...) tracelog((l_), "[{}] " fmt_, ldns_pkt_id(pkt_), ##__VA_ARGS__)
#define tracelog_fid(l_, pkt_, fmt_, ...) tracelog((l_), "[{}] " fmt_, ldns_pkt_id(pkt_), ##__VA_ARGS__)

using std::chrono::duration_cast;

namespace ag::dns {

static constexpr std::string_view MOZILLA_DOH_HOST = "use-application-dns.net.";

static constexpr uint32_t SOA_RETRY_IPV6_BLOCK = 60;

// Return filter engine params or the offending pattern
static DnsFilter::EngineParams make_fallback_filter_params(
        const std::vector<std::string> &fallback_domains, Logger &log) {
    static constexpr std::string_view CHARSET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-.*";
    std::string flt_data;
    std::string rule;
    for (auto &pattern : fallback_domains) {
        rule.clear();
        std::string_view p = ag::utils::trim(pattern);

        if (p.empty()) {
            continue;
        }

        if (auto pos = p.find_first_not_of(CHARSET); pos != p.npos) {
            dbglog(log, "Bad character '{}' in pattern '{}'", p[pos], pattern);
            continue;
        }

        auto wldpos = p.rfind('*');
        if (wldpos == p.size() - 1) {
            dbglog(log, "Wildcard at the end of pattern '{}'", pattern);
            continue;
        }
        if (wldpos != 0) {
            // If wildcard is the first char, don't append a pipe
            rule += '|';
        }

        rule += p;
        rule += '^';

        if (!DnsFilter::is_valid_rule(rule)) {
            dbglog(log, "Pattern '{}' results in an invalid rule", pattern);
            continue;
        }

        flt_data += rule;
        flt_data += "\n";
    }
    return {.filters = {{.data = std::move(flt_data), .in_memory = true}}};
}

// info not nullptr when logging incoming packet, nullptr for outgoing packets
#if !TARGET_OS_IPHONE
static void log_packet(
        const Logger &log, const ldns_pkt *packet, std::string_view pkt_name, const DnsMessageInfo *info = nullptr) {
    if (!log.is_enabled(LogLevel::LOG_LEVEL_DEBUG)) {
        return;
    }

    ldns_buffer *str_dns = ldns_buffer_new(LDNS_MAX_PACKETLEN);
    ldns_status status = ldns_pkt2buffer_str(str_dns, packet);
    if (status != LDNS_STATUS_OK) {
        dbglog_id(log, packet, "Failed to print {}: {} ({})", pkt_name, ldns_get_errorstr_by_id(status),
                magic_enum::enum_name(status));
    } else if (info) {
        dbglog_id(log, packet, "{} from {} over {}:\n{}", pkt_name, info->peername.str(),
                magic_enum::enum_name<utils::TransportProtocol>(info->proto), (char *) ldns_buffer_begin(str_dns));
    } else {
        dbglog_id(log, packet, "{}:\n{}", pkt_name, (char *) ldns_buffer_begin(str_dns));
    }
    ldns_buffer_free(str_dns);
}
#else
static void log_packet(
        const Logger &log, const ldns_pkt *packet, std::string_view pkt_name, const DnsMessageInfo *info = nullptr) {
    if (!log.is_enabled(LogLevel::LOG_LEVEL_DEBUG)) {
        return;
    }

    std::string str_dns;
    ldns_status status = [&] {
        const ldns_rr *question = ldns_rr_list_rr(ldns_pkt_question(packet), 0);
        if (!question) {
            return LDNS_STATUS_ERR;
        }
        AllocatedPtr<char> type{ldns_rr_type2str(ldns_rr_get_type(question))};
        AllocatedPtr<char> domain{ldns_rdf2str(ldns_rr_owner(question))};
        AllocatedPtr<char> rcode{ldns_pkt_rcode2str(ldns_pkt_get_rcode(packet))};
        str_dns = fmt::format("{} {} rcode: {}\n{}",
                              domain.get() ? domain.get() : "(null)",
                              type.get() ? type.get() : "(null)",
                              rcode.get() ? rcode.get() : "(null)",
                              DnsForwarderUtils::rr_list_to_string(ldns_pkt_answer(packet)));
        return LDNS_STATUS_OK;
    }();
    if (status != LDNS_STATUS_OK) {
        dbglog_id(log, packet, "Failed to print {}: {} ({})", pkt_name, ldns_get_errorstr_by_id(status),
                magic_enum::enum_name(status));
    } else if (info) {
        dbglog_id(log, packet, "{} from {} over {}: {}", pkt_name, info->peername.str(),
                  magic_enum::enum_name<utils::TransportProtocol>(info->proto), str_dns);
    } else {
        dbglog_id(log, packet, "{}: {}", pkt_name, str_dns);
    }
}
#endif

static uint16_t read_uint16_be(Uint8View pkt) {
    assert(pkt.size() >= 2);
    return pkt[0] << 8 | pkt[1];
}

static void event_append_rules(
        DnsRequestProcessedEvent &event, const std::vector<const DnsFilter::Rule *> &additional_rules) {

    if (additional_rules.empty()) {
        return;
    }

    event.rules.reserve(event.rules.size() + additional_rules.size());
    event.filter_list_ids.reserve(event.filter_list_ids.size() + additional_rules.size());

    for (auto it = additional_rules.rbegin(); it != additional_rules.rend(); ++it) {
        auto rule = *it;

        if (event.rules.cend() != std::find(event.rules.cbegin(), event.rules.cend(), rule->text)) {
            // Skip non-unique
            continue;
        }

        event.rules.insert(event.rules.begin(), rule->text);
        event.filter_list_ids.insert(event.filter_list_ids.begin(), rule->filter_id);
    }

    const auto *content = std::get_if<DnsFilter::AdblockRuleInfo>(&additional_rules[0]->content);
    event.whitelist = content != nullptr && content->props.test(DnsFilter::DARP_EXCEPTION);
}

void DnsForwarder::finalize_processed_event(DnsRequestProcessedEvent &event, const ldns_pkt *request,
        const ldns_pkt *response, const ldns_pkt *original_response, std::optional<int32_t> upstream_id,
        Error<DnsError> error) const {
    if (request != nullptr) {
        const ldns_rr *question = ldns_rr_list_rr(ldns_pkt_question(request), 0);
        AllocatedPtr<char> type{ldns_rr_type2str(ldns_rr_get_type(question))};
        event.type = type.get();
        AllocatedPtr<char> domain{ldns_rdf2str(ldns_rr_owner(question))};
        event.domain = domain.get();
    } else {
        event.type.clear();
    }

    if (response != nullptr) {
        auto status = AllocatedPtr<char>(ldns_pkt_rcode2str(ldns_pkt_get_rcode(response)));
        event.status = status != nullptr ? status.get() : "";
        event.answer = DnsForwarderUtils::rr_list_to_string(ldns_pkt_answer(response));
    } else {
        event.status.clear();
        event.answer.clear();
    }

    if (original_response != nullptr) {
        event.original_answer = DnsForwarderUtils::rr_list_to_string(ldns_pkt_answer(original_response));
    } else {
        event.original_answer.clear();
    }

    event.upstream_id = upstream_id;

    if (error) {
        dbglog(m_log, "{}", error->str());
        event.error = error->str();
    } else {
        event.error.clear();
    }

    event.elapsed = duration_cast<Millis>(SystemClock::now().time_since_epoch()).count() - event.start_time;
}

// If we know any DNS64 prefixes, request A RRs from `upstream` and
// return a synthesized AAAA response or nullptr if synthesis was unsuccessful
coro::Task<ldns_pkt_ptr> DnsForwarder::try_dns64_aaaa_synthesis(Upstream *upstream, const ldns_pkt_ptr &request) const {

    if (m_dns64_state->prefixes.empty()) {
        // No prefixes
        co_return nullptr;
    }

    const ldns_rr *question = ldns_rr_list_rr(ldns_pkt_question(request.get()), 0);
    if (!question || !ldns_rr_owner(question)) {
        dbglog_fid(m_log, request.get(), "DNS64: could not synthesize AAAA response: invalid request");
        co_return nullptr;
    }

    const ldns_pkt_ptr request_a(
            ldns_pkt_query_new(ldns_rdf_clone(ldns_rr_owner(question)), LDNS_RR_TYPE_A, LDNS_RR_CLASS_IN, 0));

    ldns_pkt_set_cd(request_a.get(), ldns_pkt_cd(request.get()));
    ldns_pkt_set_rd(request_a.get(), ldns_pkt_rd(request.get()));
    ldns_pkt_set_random_id(request_a.get());

    const auto response_a = co_await upstream->exchange(request_a.get());
    if (response_a.has_error()) {
        dbglog_fid(m_log, request.get(),
                "DNS64: could not synthesize AAAA response: upstream failed to perform A query:\n{}",
                response_a.error()->str());
        co_return nullptr;
    }

    const size_t ancount = ldns_pkt_ancount(response_a->get());
    if (ancount == 0) {
        dbglog_fid(m_log, request.get(), "DNS64: could not synthesize AAAA response: upstream returned no A records");
        co_return nullptr;
    }

    ldns_rr_list *rr_list = ldns_rr_list_new();
    size_t aaaa_rr_count = 0;
    for (size_t i = 0; i < ancount; ++i) {
        const ldns_rr *a_rr = ldns_rr_list_rr(ldns_pkt_answer(response_a->get()), i);

        if (LDNS_RR_TYPE_A != ldns_rr_get_type(a_rr)) {
            ldns_rr_list_push_rr(rr_list, ldns_rr_clone(a_rr));
            continue;
        }

        const auto rdf = ldns_rr_rdf(a_rr, 0); // first and only field
        if (!rdf) {
            continue;
        }

        const Uint8View ip4{ldns_rdf_data(rdf), ldns_rdf_size(rdf)};

        for (const Uint8Vector &pref : m_dns64_state->prefixes) {
            const auto synth_res = dns64::synthesize_ipv4_embedded_ipv6_address({pref.data(), std::size(pref)}, ip4);
            if (synth_res.has_error()) {
                dbglog_fid(m_log, request.get(), "DNS64: could not synthesize IPv4-embedded IPv6:\n{}",
                        synth_res.error()->str());
                continue; // Try the next prefix
            }
            auto &ip6 = synth_res.value();

            ldns_rr *aaaa_rr = ldns_rr_clone(a_rr);
            ldns_rr_set_type(aaaa_rr, LDNS_RR_TYPE_AAAA);
            ldns_rdf_deep_free(ldns_rr_pop_rdf(aaaa_rr)); // ip4 view becomes invalid here
            ldns_rr_push_rdf(aaaa_rr, ldns_rdf_new_frm_data(LDNS_RDF_TYPE_AAAA, ip6.size(), ip6.data()));

            ldns_rr_list_push_rr(rr_list, aaaa_rr);
            ++aaaa_rr_count;
        }
    }

    dbglog_fid(m_log, request.get(), "DNS64: synthesized AAAA RRs: {}", aaaa_rr_count);
    if (aaaa_rr_count == 0) {
        ldns_rr_list_free(rr_list);
        co_return nullptr;
    }

    ldns_pkt *aaaa_resp = ldns_pkt_new();
    ldns_pkt_set_id(aaaa_resp, ldns_pkt_id(request.get()));
    ldns_pkt_set_rd(aaaa_resp, ldns_pkt_rd(request.get()));
    ldns_pkt_set_ra(aaaa_resp, ldns_pkt_ra(response_a->get()));
    ldns_pkt_set_cd(aaaa_resp, ldns_pkt_cd(response_a->get()));
    ldns_pkt_set_qr(aaaa_resp, true);

    ldns_rr_list_deep_free(ldns_pkt_question(aaaa_resp));
    ldns_pkt_set_qdcount(aaaa_resp, ldns_pkt_qdcount(request.get()));
    ldns_pkt_set_question(aaaa_resp, ldns_pkt_get_section_clone(request.get(), LDNS_SECTION_QUESTION));

    ldns_rr_list_deep_free(ldns_pkt_answer(aaaa_resp));
    ldns_pkt_set_ancount(aaaa_resp, ldns_rr_list_rr_count(rr_list));
    ldns_pkt_set_answer(aaaa_resp, rr_list);

    co_return ldns_pkt_ptr(aaaa_resp);
}

static Uint8Vector transform_response_to_raw_data(const ldns_pkt *response) {
    ldns_buffer *buffer = ldns_buffer_new(LDNS_MAX_PACKETLEN);
    ldns_status status = ldns_pkt2buffer_wire(buffer, response);
    assert(status == LDNS_STATUS_OK);
    // @todo: custom allocator will allow to avoid data copy
    Uint8Vector data = {ldns_buffer_at(buffer, 0), ldns_buffer_at(buffer, 0) + ldns_buffer_position(buffer)};
    ldns_buffer_free(buffer);
    return data;
}

DnsForwarder::DnsForwarder() = default;

DnsForwarder::~DnsForwarder() = default;

static coro::Task<void> discover_dns64_prefixes(std::vector<UpstreamOptions> uss, Millis timeout,
        std::shared_ptr<SocketFactory> socket_factory, dns64::StatePtr state, EventLoop &loop, uint32_t max_tries,
        Millis wait_time, std::weak_ptr<bool> shutdown_guard);

DnsForwarder::InitResult DnsForwarder::init(
        EventLoopPtr loop, const DnsProxySettings &settings, const DnsProxyEvents &events) {
    m_log = ag::Logger{"DNS forwarder"};
    m_loop = std::move(loop);
    m_shutdown_guard = std::make_shared<bool>(true);
    infolog(m_log, "Initializing forwarder...");

    m_settings = &settings;
    m_events = &events;

    if (!settings.custom_blocking_ipv4.empty() && !utils::is_valid_ip4(settings.custom_blocking_ipv4)) {
        this->deinit();
        return {false, make_error(DnsProxyInitError::AE_INVALID_IPV4, AG_FMT("{}", settings.custom_blocking_ipv4))};
    }
    if (!settings.custom_blocking_ipv6.empty() && !utils::is_valid_ip6(settings.custom_blocking_ipv6)) {
        this->deinit();
        return {false, make_error(DnsProxyInitError::AE_INVALID_IPV6, AG_FMT("{}", settings.custom_blocking_ipv6))};
    }

    struct SocketFactory::Parameters sf_parameters = {.loop = *m_loop};
    sf_parameters.enable_route_resolver = settings.enable_route_resolver;
    if (events.on_certificate_verification != nullptr) {
        dbglog(m_log, "Using application_verifier");
        sf_parameters.verifier = std::make_unique<ApplicationVerifier>(m_events->on_certificate_verification);
    } else {
        dbglog(m_log, "Using default_verifier");
        sf_parameters.verifier = std::make_unique<DefaultVerifier>();
    }

    if (settings.outbound_proxy.has_value()) {
        sf_parameters.oproxy = {
                .settings = &m_settings->outbound_proxy.value(),
                .bootstrapper = std::make_unique<ProxyBootstrapper>(*m_loop, *m_settings, *m_events, m_shutdown_guard),
        };
    }

    m_socket_factory = std::make_shared<SocketFactory>(std::move(sf_parameters));

    infolog(m_log, "Initializing upstreams...");
    UpstreamFactory us_factory({
            *m_loop,
            m_socket_factory.get(),
            m_settings->ipv6_available,
            m_settings->enable_http3,
            m_settings->upstream_timeout,
    });
    m_upstreams.reserve(settings.upstreams.size());
    m_fallbacks.reserve(settings.fallbacks.size());
    for (const UpstreamOptions &options : settings.upstreams) {
        infolog(m_log, "Initializing upstream {}...", options.address);
#ifdef __APPLE__
#if TARGET_OS_IPHONE && defined _BUILDING_DNSPROXY_FRAMEWORK
        if (std::holds_alternative<std::monostate>(options.outbound_interface)) {
            errlog(m_log, "Failed to create upstream: outbound network interface isn't specified");
            continue;
        }
#endif // TARGET_OS_IPHONE
#endif // __APPLE__
        auto upstream_result = us_factory.create_upstream(options);
        if (upstream_result.has_error()) {
            errlog(m_log, "Failed to create upstream: {}", upstream_result.error()->str());
        } else {
            m_upstreams.emplace_back(std::move(upstream_result.value()));
            infolog(m_log, "Upstream created successfully");
        }
    }
    for (const UpstreamOptions &options : settings.fallbacks) {
        infolog(m_log, "Initializing fallback upstream {}...", options.address);
        auto upstream_result = us_factory.create_upstream(options);
        if (upstream_result.has_error()) {
            errlog(m_log, "Failed to create fallback upstream: {}", upstream_result.error()->str());
        } else {
            m_fallbacks.emplace_back(std::move(upstream_result.value()));
            infolog(m_log, "Fallback upstream created successfully");
        }
    }
    if (m_upstreams.empty() && (m_fallbacks.empty() || !settings.enable_fallback_on_upstreams_failure)) {
        this->deinit();
        return {false, make_error(DnsProxyInitError::AE_UPSTREAM_INIT_ERROR)};
    }
    infolog(m_log, "Upstreams initialized");

    infolog(m_log, "Initializing the filtering module...");
    auto [handle, err_or_warn] = m_filter.create(settings.filter_params);
    if (!handle) {
        this->deinit();
        return {false, err_or_warn};
    }
    m_filter_handle = handle;
    if (err_or_warn) {
        warnlog(m_log, "Filtering module initialized with warnings:\n{}", err_or_warn->str());
    } else {
        infolog(m_log, "Filtering module initialized");
    }

    if (!settings.fallback_domains.empty()) {
        infolog(m_log, "Initializing the fallback filter...");
        auto params = make_fallback_filter_params(settings.fallback_domains, m_log);
        auto [fallback_handle, fallback_err_or_warn] = m_filter.create(params);
        if (fallback_err_or_warn) { // Fallback filter must initialize cleanly, warnings are errors
            this->deinit();
            return {false, make_error(DnsProxyInitError::AE_FALLBACK_FILTER_INIT_ERROR, fallback_err_or_warn)};
        }
        m_fallback_filter_handle = fallback_handle;
    }

    m_dns64_state = std::make_shared<dns64::State>();
    if (settings.dns64.has_value()) {
        infolog(m_log, "DNS64 discovery is enabled");
        coro::run_detached(discover_dns64_prefixes(settings.dns64->upstreams, settings.dns64->timeout, m_socket_factory,
                m_dns64_state, *m_loop, settings.dns64->max_tries, settings.dns64->wait_time, m_shutdown_guard));
    }

    m_response_cache.set_capacity(m_settings->dns_cache_size);

    m_random_engine.seed(std::random_device{}());

    infolog(m_log, "Forwarder initialized");
    return {true, err_or_warn};
}

static coro::Task<void> discover_dns64_prefixes(std::vector<UpstreamOptions> uss, Millis timeout,
        std::shared_ptr<SocketFactory> socket_factory, dns64::StatePtr state, EventLoop &loop, uint32_t max_tries,
        Millis wait_time, std::weak_ptr<bool> shutdown_guard) {
    static ag::Logger logger{"DNS64"};
    co_await loop.co_submit();
    if (shutdown_guard.expired()) {
        co_return;
    }
    UpstreamFactory us_factory({.loop = loop, .socket_factory = socket_factory.get(), .timeout = timeout});
    auto i = max_tries;
    while (i--) {
        co_await loop.co_sleep(wait_time);
        if (shutdown_guard.expired()) {
            co_return;
        }
        for (auto &us : uss) {
            {
                auto upstream_result = us_factory.create_upstream(us);
                if (upstream_result.has_error()) {
                    dbglog(logger, "Failed to create DNS64 upstream: {}", upstream_result.error()->str());
                    continue;
                }
                state->discovering_upstream = std::move(upstream_result.value());
            }

            auto result = co_await dns64::discover_prefixes(state->discovering_upstream);
            if (shutdown_guard.expired()) {
                co_return;
            }
            state->discovering_upstream.reset();
            if (result.has_error()) {
                dbglog(logger, "Error discovering prefixes:\n{}", result.error()->str());
                continue;
            }

            if (result->empty()) {
                dbglog(logger, "No prefixes discovered, retrying");
                continue;
            }

            state->prefixes = std::move(result.value());

            infolog(logger, "Prefixes discovered: {}", state->prefixes.size());
            co_return;
        }
    }

    dbglog(logger, "Failed to discover any prefixes");
}

void DnsForwarder::deinit() {
    infolog(m_log, "Deinitializing...");

    m_settings = nullptr;
    m_shutdown_guard.reset();

    infolog(m_log, "Destroying DNS64 state...");
    if (m_dns64_state) {
        m_dns64_state->discovering_upstream.reset();
    }
    infolog(m_log, "Done");

    infolog(m_log, "Destroying upstreams...");
    m_upstreams.clear();
    infolog(m_log, "Done");

    infolog(m_log, "Destroying fallback upstreams...");
    m_fallbacks.clear();
    infolog(m_log, "Done");

    infolog(m_log, "Deinitilizing socket factory...");
    if (m_socket_factory != nullptr) {
        m_socket_factory->deinit();
    }
    infolog(m_log, "Done");

    infolog(m_log, "Destroying DNS filter...");
    m_filter.destroy(std::exchange(m_filter_handle, nullptr));
    infolog(m_log, "Done");

    infolog(m_log, "Destroying fallback filter...");
    m_filter.destroy(std::exchange(m_fallback_filter_handle, nullptr));
    infolog(m_log, "Done");

    infolog(m_log, "Clearing cache...");
    m_response_cache.clear();
    infolog(m_log, "Done");

    infolog(m_log, "Deinitialized");
}

static ldns_rr_type question_rr_type(const ldns_pkt *request) {
    return ldns_rr_get_type(ldns_rr_list_rr(ldns_pkt_question(request), 0));
}

coro::Task<DnsForwarder::HandleMessageResult> DnsForwarder::handle_message_internal(
        ldns_pkt_ptr request, std::optional<DnsMessageInfo> info, bool fallback_only) {
    std::weak_ptr<bool> guard = m_shutdown_guard;
    DnsRequestProcessedEvent event;

    log_packet(m_log, request.get(), "Handling message", opt_as_ptr(info));

    const ldns_rr *question = ldns_rr_list_rr(ldns_pkt_question(request.get()), 0);
    if (question == nullptr) {
        ldns_pkt_ptr response{ResponseHelpers::create_servfail_response(request.get())};
        log_packet(m_log, response.get(), "Server failure response");
        finalize_processed_event(
                event, nullptr, response.get(), nullptr, std::nullopt, make_error(DnsError::AE_DECODE_ERROR));
        Uint8Vector raw_response = transform_response_to_raw_data(response.get());
        co_return {std::move(raw_response), std::move(event)};
    }

    auto domain = AllocatedPtr<char>(ldns_rdf2str(ldns_rr_owner(question)));

    std::string_view normalized_domain = domain.get();
    if (ldns_dname_str_absolute(domain.get())) {
        normalized_domain.remove_suffix(1); // drop trailing dot
    }

    ResponseCache::Result cached;

    // Skip caching for transparent filtering
    if (!info || !info->transparent) {
        cached = m_response_cache.get(request.get());
    }

    if (cached.response && (!cached.expired || m_settings->optimistic_cache)) {
        log_packet(m_log, cached.response.get(), "Cached response");
        event.cache_hit = true;
        truncate_response(cached.response.get(), request.get(), opt_as_ptr(info));
        finalize_processed_event(event, request.get(), cached.response.get(), nullptr, cached.upstream_id, {});
        Uint8Vector raw_response = transform_response_to_raw_data(cached.response.get());
        if (cached.expired) {
            assert(m_settings->optimistic_cache);
            this->optimistic_cache_background_resolve(std::move(request), std::string{normalized_domain})
                    .run_detached();
        }
        co_return {std::move(raw_response), std::move(event)};
    }

    const ldns_rr_type type = ldns_rr_get_type(question);

    // disable Mozilla DoH
    if ((type == LDNS_RR_TYPE_A || type == LDNS_RR_TYPE_AAAA) && 0 == strcmp(domain.get(), MOZILLA_DOH_HOST.data())) {
        ldns_pkt_ptr response{ResponseHelpers::create_nxdomain_response(request.get(), m_settings)};
        log_packet(m_log, response.get(), "Mozilla DOH blocking response");
        Uint8Vector raw_response = transform_response_to_raw_data(response.get());
        finalize_processed_event(event, request.get(), response.get(), nullptr, std::nullopt, {});
        co_return {std::move(raw_response), std::move(event)};
    }

    tracelog_fid(m_log, request.get(), "Query domain: {}", normalized_domain);

    std::vector<DnsFilter::Rule> effective_rules;

    ldns_pkt_ptr ctx_response;
    FilterContext ctx {
        .match = {.domain = normalized_domain, .rr_type = question_rr_type(request.get())},
        .request = request,
        .response = ctx_response,
        .event = event,
        .last_effective_rules = effective_rules,
        .fallback_only = fallback_only,
    };

    if (!ldns_pkt_qr(ctx.request.get())) {
        auto filter_response = co_await apply_filter_to_request(ctx);
        if (guard.expired()) {
            co_return {};
        }

        // IPv6 blocking
        if (m_settings->block_ipv6 && LDNS_RR_TYPE_AAAA == type
                && (!filter_response || ldns_pkt_get_rcode(filter_response.get()) == LDNS_RCODE_NOERROR)) {
            dbglog_fid(m_log, ctx.request.get(), "AAAA DNS query blocked because IPv6 blocking is enabled");
            ldns_pkt_ptr soa_response{
                    ResponseHelpers::create_soa_response(ctx.request.get(), m_settings, SOA_RETRY_IPV6_BLOCK)};
            log_packet(m_log, soa_response.get(), "IPv6 blocking response");
            finalize_processed_event(event, ctx.request.get(), soa_response.get(), nullptr, std::nullopt);
            co_return {transform_response_to_raw_data(soa_response.get()), std::move(event)};
        }

        if (filter_response) {
            finalize_processed_event(event, ctx.request.get(), filter_response.get(), nullptr, std::nullopt);
            co_return {transform_response_to_raw_data(filter_response.get()), std::move(event)};
        }
    }

    bool is_our_do_bit = m_settings->enable_dnssec_ok && DnssecHelpers::set_do_bit(ctx.request.get());

    UpstreamExchangeResult exchange_result;

    // Don't do upstream exchange for transparent filtering
    if (info && info->transparent) {
        if (!ldns_pkt_qr(ctx.request.get())) {
            // This is a query. Return the modified request to the caller.
            dbglog_fid(m_log, ctx.request.get(), "Returning processed request (transparent filtering)");
            co_return {transform_response_to_raw_data(ctx.request.get()), std::move(event)};
        }
        // This is a response. Treat it as if it came from the upstream.
        exchange_result.result = ldns_pkt_ptr{ldns_pkt_clone(ctx.request.get())};
    } else {
        // If this is a retransmitted request, use fallback upstreams only
        exchange_result =
                co_await do_upstreams_exchange(normalized_domain, ctx.request.get(), ctx.fallback_only, opt_as_ptr(info));
    }

    auto &[response, selected_upstream] = exchange_result;
    if (guard.expired()) {
        co_return {};
    }

    if (!response) {
        auto err = response.error();
        if (err->value() == DnsError::AE_TIMED_OUT) {
            co_return {.timed_out = true};
        }
        if (!m_settings->enable_servfail_on_upstreams_failure) {
            dbglog_fid(m_log, ctx.request.get(), "Not responding, upstreams exchange error: {}", err->str());
            co_return {};
        }
        response = ldns_pkt_ptr{ResponseHelpers::create_servfail_response(ctx.request.get())};
        log_packet(m_log, response->get(), "Server failure response");
        finalize_processed_event(event, ctx.request.get(), response->get(), nullptr,
                selected_upstream ? std::make_optional(selected_upstream->options().id) : std::nullopt,
                make_error(DnsError::AE_EXCHANGE_ERROR, err));
        co_return {transform_response_to_raw_data(response->get()), std::move(event)};
    }

    ctx.response = std::move(response.value());
    log_packet(m_log, ctx.response.get(),
            AG_FMT("Upstream ({}) response", selected_upstream ? selected_upstream->options().address : "<transparent>")
                    .c_str());

    event.bytes_sent = ldns_pkt_size(ctx.request.get());
    event.bytes_received = ldns_pkt_size(ctx.response.get());
    event.dnssec = finalize_dnssec_log_logic(ctx.response.get(), is_our_do_bit);

    if (LDNS_RCODE_NOERROR == ldns_pkt_get_rcode(ctx.response.get())) {
        auto filter_response =
                co_await handle_response(ctx, selected_upstream, normalized_domain, type, opt_as_ptr(info));
        if (guard.expired()) {
            co_return {};
        }
        if (filter_response) {
            co_return {transform_response_to_raw_data(filter_response.get()), std::move(event)};
        }
    }

    truncate_response(ctx.response.get(), ctx.request.get(), opt_as_ptr(info));
    finalize_processed_event(event, ctx.request.get(), ctx.response.get(), nullptr,
            selected_upstream ? std::make_optional(selected_upstream->options().id) : std::nullopt);
    auto response_wire = transform_response_to_raw_data(ctx.response.get());
    if (!info || !info->transparent) {
        assert(selected_upstream);
        m_response_cache.put(ctx.request.get(), std::move(ctx.response), selected_upstream->options().id);
    }
    co_return {std::move(response_wire), std::move(event)};
}

coro::Task<ldns_pkt_ptr> DnsForwarder::apply_cname_filter(FilterContext &ctx, const ldns_rr *cname_rr) {
    assert(ldns_rr_get_type(cname_rr) == LDNS_RR_TYPE_CNAME);

    const auto *rdf = ldns_rr_rdf(cname_rr, 0);
    if (!rdf) {
        co_return nullptr;
    }

    AllocatedPtr<char> cname_ptr(ldns_rdf2str(rdf));
    if (!cname_ptr) {
        co_return nullptr;
    }

    std::string_view cname = cname_ptr.get();
    if (ldns_dname_str_absolute(cname_ptr.get())) {
        cname.remove_suffix(1); // drop trailing dot
    }

    tracelog_fid(m_log, ctx.request.get(), "Response CNAME: {}", cname);

    ctx.match = {
            .domain = cname,
            .rr_type = LDNS_RR_TYPE_CNAME,
    };
    co_return co_await apply_filter_to_response(ctx);
}

coro::Task<ldns_pkt_ptr> DnsForwarder::apply_https_filter(
        FilterContext &ctx, const ldns_rr *rr, std::string_view domain) {
    assert(ldns_rr_get_type(rr) == LDNS_RR_TYPE_HTTPS);
    std::weak_ptr<bool> guard = m_shutdown_guard;

    ctx.match = {.domain = domain, .rr_type = ldns_rr_get_type(rr)};
    auto filter_response = co_await apply_filter_to_response(ctx);
    if (guard.expired()) {
        co_return nullptr;
    }
    if (filter_response) {
        co_return filter_response;
    }

    auto hints = SvcbHttpsHelpers::get_ip_hints_from_response(ctx.response.get());
    for (auto &ip : hints) {
        tracelog_fid(m_log, ctx.request.get(), "Response IP: {}", ip);
        ctx.match = {.domain = ip, .rr_type = ldns_rr_get_type(rr)};
        filter_response = co_await apply_filter_to_response(ctx);
        if (guard.expired()) {
            co_return nullptr;
        }
        if (filter_response) {
            co_return filter_response;
        }
    }

    co_return nullptr;
}

coro::Task<ldns_pkt_ptr> DnsForwarder::apply_ip_filter(FilterContext &ctx, const ldns_rr *rr) {
    assert(ldns_rr_get_type(rr) == LDNS_RR_TYPE_A || ldns_rr_get_type(rr) == LDNS_RR_TYPE_AAAA);

    auto rdf = ldns_rr_rdf(rr, 0);
    if (!rdf || (ldns_rdf_size(rdf) != IPV4_ADDRESS_SIZE && ldns_rdf_size(rdf) != IPV6_ADDRESS_SIZE)) {
        co_return nullptr;
    }
    Uint8View addr{ldns_rdf_data(rdf), ldns_rdf_size(rdf)};
    std::string addr_str = ag::utils::addr_to_str(addr);

    tracelog_fid(m_log, ctx.request.get(), "Response IP: {}", addr_str);

    ctx.match = {.domain = addr_str, .rr_type = ldns_rr_get_type(rr)};
    co_return co_await apply_filter_to_response(ctx);
}

coro::Task<ldns_pkt_ptr> DnsForwarder::apply_filter_to_request(FilterContext &ctx) {
    ldns_rr *question = ldns_rr_list_rr(ldns_pkt_question(ctx.request.get()), 0);
    if (ldns_rr_get_type(question) == LDNS_RR_TYPE_HTTPS
            && m_settings->adblock_rules_blocking_mode == DnsProxyBlockingMode::ADDRESS) {
        tracelog_fid(m_log, ctx.request.get(), "Wait HTTPS response to apply filter again");
        co_return nullptr;
    }
    co_return co_await apply_filter(ctx);
}

coro::Task<ldns_pkt_ptr> DnsForwarder::apply_filter_to_response(FilterContext &ctx) {
    co_return co_await apply_filter(ctx);
}

coro::Task<ldns_pkt_ptr> DnsForwarder::handle_response(FilterContext &ctx, Upstream *upstream,
        std::string_view normalized_domain, const ldns_rr_type type, const DnsMessageInfo *info) {
    std::weak_ptr<bool> guard = m_shutdown_guard;
    const auto ancount = ldns_pkt_ancount(ctx.response.get());
    for (size_t i = 0; i < ancount; ++i) {
        // CNAME response blocking
        auto rr = ldns_rr_list_rr(ldns_pkt_answer(ctx.response.get()), i);
        if (ldns_rr_get_type(rr) == LDNS_RR_TYPE_CNAME) {
            auto filter_response = co_await apply_cname_filter(ctx, rr);
            if (guard.expired()) {
                co_return {};
            }
            if (filter_response) {
                finalize_processed_event(ctx.event, ctx.request.get(), filter_response.get(), ctx.response.get(),
                        upstream ? std::make_optional(upstream->options().id) : std::nullopt, nullptr);
                co_return filter_response;
            }
        }
        // IP response blocking
        if (ldns_rr_get_type(rr) == LDNS_RR_TYPE_A || ldns_rr_get_type(rr) == LDNS_RR_TYPE_AAAA) {
            auto filter_response = co_await apply_ip_filter(ctx, rr);
            if (guard.expired()) {
                co_return {};
            }
            if (filter_response) {
                finalize_processed_event(ctx.event, ctx.request.get(), filter_response.get(), ctx.response.get(),
                        upstream ? std::make_optional(upstream->options().id) : std::nullopt, nullptr);
                co_return filter_response;
            }
        }
        // HTTPS response blocking
        if (ldns_rr_get_type(rr) == LDNS_RR_TYPE_HTTPS) {
            auto filter_response = co_await apply_https_filter(ctx, rr, normalized_domain);
            if (guard.expired()) {
                co_return {};
            }
            if (filter_response) {
                if (std::optional override = info != nullptr ? info->settings_overrides.block_ech : std::nullopt;
                        override.value_or(m_settings->block_ech)) {
                    if (SvcbHttpsHelpers::remove_ech_svcparam(filter_response.get())) {
                        dbglog_fid(m_log, filter_response.get(), "Removed ECH parameters from SVCB/HTTPS RR");
                    }
                }
                finalize_processed_event(ctx.event, ctx.request.get(), filter_response.get(), ctx.response.get(),
                        upstream ? std::make_optional(upstream->options().id) : std::nullopt, nullptr);
                co_return filter_response;
            }
        }
    }
    // DNS64 synthesis. Don't do it when filtering transparently.
    if (m_settings->dns64.has_value() && LDNS_RR_TYPE_AAAA == type && (!info || !info->transparent)) {
        bool has_aaaa = false;
        for (size_t i = 0; i < ancount; ++i) {
            auto rr = ldns_rr_list_rr(ldns_pkt_answer(ctx.response.get()), i);
            if (ldns_rr_get_type(rr) == LDNS_RR_TYPE_AAAA) {
                has_aaaa = true;
            }
        }
        if (!has_aaaa) {
            assert(upstream);
            auto synth_response = co_await try_dns64_aaaa_synthesis(upstream, ctx.request);
            if (guard.expired()) {
                co_return {};
            }
            if (synth_response) {
                ctx.response = std::move(synth_response);
                log_packet(m_log, ctx.response.get(), "DNS64 synthesized response");
            }
        }
    }
    if (std::optional override = info != nullptr ? info->settings_overrides.block_ech : std::nullopt;
            override.value_or(m_settings->block_ech)) {
        if (SvcbHttpsHelpers::remove_ech_svcparam(ctx.response.get())) {
            dbglog_fid(m_log, ctx.response.get(), "Removed ECH parameters from SVCB/HTTPS RR");
        }
    }
    co_return {};
}

coro::Task<ldns_pkt_ptr> DnsForwarder::apply_filter(FilterContext &ctx) {

    auto rules = m_filter.match(m_filter_handle, ctx.match);
    for (const DnsFilter::Rule &rule : rules) {
        tracelog_fid(m_log, ctx.request.get(), "Matched rule: {}", rule.text);
    }
    rules.insert(rules.end(), std::make_move_iterator(ctx.last_effective_rules.begin()),
            std::make_move_iterator(ctx.last_effective_rules.end()));
    ctx.last_effective_rules.clear();

    auto effective_rules = DnsFilter::get_effective_rules(rules);

    std::optional<DnsFilter::ApplyDnsrewriteResult::RewriteInfo> rewrite_info;
    if (!effective_rules.dnsrewrite.empty()) {
        auto rewrite_result = DnsFilter::apply_dnsrewrite_rules(effective_rules.dnsrewrite);
        for (const DnsFilter::Rule *rule : rewrite_result.rules) {
            tracelog_fid(m_log, ctx.request.get(), "Applied $dnsrewrite: {}", rule->text);
        }
        effective_rules.dnsrewrite = std::move(rewrite_result.rules);
        rewrite_info = std::move(rewrite_result.rewritten_info);
    }

    ctx.last_effective_rules.reserve(effective_rules.dnsrewrite.size() + effective_rules.leftovers.size());
    std::transform(effective_rules.dnsrewrite.begin(), effective_rules.dnsrewrite.end(),
            std::back_inserter(ctx.last_effective_rules), [](const DnsFilter::Rule *r) {
                return *r;
            });
    std::transform(effective_rules.leftovers.begin(), effective_rules.leftovers.end(),
            std::back_inserter(ctx.last_effective_rules), [](const DnsFilter::Rule *r) {
                return *r;
            });

    event_append_rules(ctx.event, effective_rules.dnsrewrite);
    if (!rewrite_info.has_value()) {
        event_append_rules(ctx.event, effective_rules.leftovers);
    }

    if (const DnsFilter::AdblockRuleInfo * content; !rewrite_info.has_value()
            && (effective_rules.leftovers.empty()
                    || (nullptr
                                    != (content = std::get_if<DnsFilter::AdblockRuleInfo>(
                                                &effective_rules.leftovers[0]->content))
                            && content->props.test(DnsFilter::DARP_EXCEPTION)))) {
        co_return nullptr;
    }

    if (effective_rules.dnsrewrite.empty()) {
        dbglog_fid(m_log, ctx.request.get(), "DNS query blocked by rule: {}", effective_rules.leftovers[0]->text);
    } else {
        dbglog_fid(m_log, ctx.request.get(), "DNS query blocked by $dnsrewrite rule(s): num={}",
                effective_rules.dnsrewrite.size());
    }

    if (rewrite_info.has_value() && rewrite_info->cname.has_value()) {
        ldns_pkt_ptr rewritten_request{ldns_pkt_clone(ctx.request.get())};
        ldns_rr *question = ldns_rr_list_rr(ldns_pkt_question(rewritten_request.get()), 0);
        ldns_rdf_deep_free(ldns_rr_owner(question));
        ldns_rr_set_owner(question, ldns_dname_new_frm_str(rewrite_info->cname->c_str()));
        std::string_view rwr_cname = *rewrite_info->cname;
        if (rwr_cname.back() == '.') {
            rwr_cname.remove_suffix(1);
        }

        log_packet(m_log, rewritten_request.get(), "Rewritten cname request");

        auto [response, _] =
                co_await this->do_upstreams_exchange(rwr_cname, rewritten_request.get(), ctx.fallback_only);
        if (!response) {
            dbglog_id(m_log, rewritten_request.get(), "Failed to resolve rewritten cname: {}", response.error()->str());
            co_return nullptr;
        }

        log_packet(m_log, rewritten_request.get(), "Rewritten cname response");
        for (size_t i = 0; i < ldns_pkt_ancount(response->get()); ++i) {
            ldns_rr *rr = ldns_rr_list_rr(ldns_pkt_answer(response->get()), i);
            if (ldns_rr_get_type(rr) == ldns_rr_get_type(question)) {
                rewrite_info->rrs.emplace_back(ldns_rr_clone(rr));
            }
        }
    }

    ldns_pkt_ptr response{ResponseHelpers::create_blocking_response(
            ctx.request.get(), ctx.response.get(), m_settings, effective_rules.leftovers, std::move(rewrite_info))};
    log_packet(m_log, response.get(), "Rule blocked response");
    co_return response;
}

#ifdef ANDROID
[[clang::optnone]]
#endif
coro::Task<UpstreamExchangeResult>
DnsForwarder::do_upstream_exchange(
        Upstream *upstream, const ldns_pkt *request, const DnsMessageInfo *info, Millis error_rtt) {
    tracelog_id(m_log, request, "Upstream [{}] ({}) exchange starting", upstream->options().id,
            upstream->options().address);
    std::weak_ptr<bool> guard = m_shutdown_guard;
    ag::utils::Timer timer;
    auto result = co_await upstream->exchange(request, info);
    auto elapsed = timer.elapsed<Millis>();
    if (guard.expired()) {
        co_return {make_error(DnsError::AE_SHUTTING_DOWN), nullptr};
    }
    tracelog_id(
            m_log, request, "Upstream [{}] ({}) exchange done", upstream->options().id, upstream->options().address);

    // They say it's normal for a server to close connection unexpectedly:
    // https://github.com/AdguardTeam/DnsLibs/issues/86
    // Give it one more chance if that is what happened.
    if (result.has_error()
            && (result.error()->value() == DnsError::AE_CONNECTION_CLOSED
                    || result.error()->value() == DnsError::AE_CURL_ERROR)) {
        tracelog_id(m_log, request, "Upstream [{}] ({}) exchange retry starting", upstream->options().id,
                upstream->options().address);
        timer.reset();
        result = co_await upstream->exchange(request, info);
        elapsed = timer.elapsed<Millis>();
        if (guard.expired()) {
            co_return {make_error(DnsError::AE_SHUTTING_DOWN), nullptr};
        }
        tracelog_id(m_log, request, "Upstream [{}] ({}) exchange retry done", upstream->options().id,
                upstream->options().address);
    }

    if (result.has_error()
            && (result.error()->value() == DnsError::AE_TIMED_OUT)) {
        dbglog_id(m_log, request, "Upstream [{}] ({}) exchange timed out", upstream->options().id,
                    upstream->options().address);
    }

    if (result.has_error()) {
        upstream->update_rtt_estimate(error_rtt + elapsed);
    } else {
        upstream->update_rtt_estimate(elapsed);
    }

    co_return {std::move(result), upstream};
}

// Take a shared pointer to a request to prolong its life after the parent function returns after receiving
// the first succesful exchange result. Because currently there's no way to cancel the other exchanges.
coro::Task<UpstreamExchangeResult> DnsForwarder::do_upstream_exchange_shared(
        Upstream *upstream, std::shared_ptr<const ldns_pkt> request, const DnsMessageInfo *info, Millis error_rtt) {
    co_return co_await do_upstream_exchange(upstream, request.get(), info, error_rtt);
}

// Do exchanges with all `upstreams` in parallel.
// If `wait_all` is `false`, return the first non-error exchange result.
// If `wait_all` is `true`, wait for all exchange results and return the first one that is
// not an error, and does not contain an error DNS response (SERVFAIL/NXDOMAIN/etc.).
// In both cases if the aforementioned results are not available, return an error.
coro::Task<UpstreamExchangeResult> DnsForwarder::do_parallel_exchange(const std::vector<Upstream *> &upstreams,
        const ldns_pkt *request, const DnsMessageInfo *info, Millis error_rtt, bool wait_all) {
    std::weak_ptr<bool> guard = m_shutdown_guard;
    if (wait_all) {
        auto all_of = parallel::all_of<UpstreamExchangeResult>();
        for (Upstream *upstream : upstreams) {
            all_of.add(do_upstream_exchange(upstream, request, info, error_rtt));
        }
        std::vector<UpstreamExchangeResult> results = co_await all_of;
        if (guard.expired()) {
            co_return {make_error(DnsError::AE_SHUTTING_DOWN), nullptr};
        }
        std::sort(results.begin(), results.end(), [](const UpstreamExchangeResult &l, const UpstreamExchangeResult &r) {
            if (l.result.has_error()) {
                return false; // Error result never wins.
            }
            if (r.result.has_error()) {
                return true; // A non-error result always wins against an error result.
            }
            ldns_pkt_rcode lcode = ldns_pkt_get_rcode(l.result.value().get());
            ldns_pkt_rcode rcode = ldns_pkt_get_rcode(r.result.value().get());
            if (lcode == rcode) {
                if (lcode == LDNS_RCODE_NOERROR) { // If both are NOERROR, the one with more answers wins.
                    return ldns_pkt_ancount(l.result.value().get()) > ldns_pkt_ancount(r.result.value().get());
                }
                return false; // If RCODEs are the same, no one wins.
            }
            return lcode == LDNS_RCODE_NOERROR; // If RCODEs are different, NOERROR wins.
        });
        co_return std::move(results.front());
    }
    std::optional<UpstreamExchangeResult> last_error;
    auto any_of_cond = parallel::any_of_cond<UpstreamExchangeResult>([&last_error](const UpstreamExchangeResult &r) {
        if (r.result.has_error()) {
            last_error = {r.result.error(), r.upstream};
            return false;
        }
        return true;
    });
    std::shared_ptr<const ldns_pkt> request_shared{ldns_pkt_clone(request), &ldns_pkt_free};
    for (Upstream *upstream : upstreams) {
        any_of_cond.add(do_upstream_exchange_shared(upstream, request_shared, info, error_rtt));
    }
    std::optional<UpstreamExchangeResult> result = co_await any_of_cond;
    if (guard.expired()) {
        co_return {make_error(DnsError::AE_SHUTTING_DOWN), nullptr};
    }
    if (!result) {
        if (last_error) {
            co_return std::move(*last_error);
        } else {
            co_return UpstreamExchangeResult{
                    .result = make_error(DnsError::AE_INTERNAL_ERROR, "No upstreams have been asked"),
            };
        }
    }
    co_return std::move(*result);
}

static std::tuple<std::vector<Upstream *>, Millis, bool> collect_upstreams(const std::vector<UpstreamPtr> &src, bool fallback) {
    Millis max_rtt{0};
    Millis min_rtt = Millis::max();
    bool has_unestimated = false;
    std::vector<Millis> src_rtts{src.size(), Millis{0}};
    // Calculate min estimate
    for (size_t i = 0; i != src.size(); i++) {
        auto rtt_estimate = src[i]->rtt_estimate();
        if (rtt_estimate) {
            src_rtts[i] = *rtt_estimate;
        } else {
            has_unestimated = true;
        }
        min_rtt = std::min(min_rtt, src_rtts[i]);
    }

    // Build upstream list
    std::vector<Upstream *> upstreams;
    upstreams.reserve(src.size());
    for (size_t i = 0; i != src.size(); i++) {
        auto rtt = src_rtts[i];
        max_rtt = std::max(max_rtt, rtt);
        upstreams.push_back(src[i].get());
    }
    return {std::move(upstreams), max_rtt, has_unestimated};
}

coro::Task<UpstreamExchangeResult> DnsForwarder::do_upstreams_exchange(
        std::string_view normalized_domain, const ldns_pkt *request, bool force_fallback, const DnsMessageInfo *info) {
    bool fallback = !m_fallbacks.empty() && (force_fallback || apply_fallback_filter(normalized_domain, request));
    std::optional<UpstreamExchangeResult> last_result;
    if (!fallback) {
        auto [upstreams_to_query, max_rtt, has_unestimated] = collect_upstreams(m_upstreams, false);
        // Fallbacks are always queried in parallel with `wait_all` enabled.
        std::weak_ptr<bool> guard = m_shutdown_guard;
        if (has_unestimated || m_settings->enable_parallel_upstream_queries) {
            last_result = co_await do_parallel_exchange(upstreams_to_query, request, info, 2 * max_rtt, /*wait_all*/ false);
            if (guard.expired()) {
                co_return {make_error(DnsError::AE_SHUTTING_DOWN), nullptr};
            }
            if (last_result->result.has_value()) {
                co_return std::move(*last_result);
            }
        } else {
            // Weighted random load balancing below.
            std::vector<double> upstream_weights(upstreams_to_query.size(), 1.0);
            while (!upstreams_to_query.empty()) {
                for (size_t i = 0; i < upstreams_to_query.size(); ++i) {
                    auto rtt = upstreams_to_query[i]->rtt_estimate();
                    if (rtt.has_value()) {
                        upstream_weights[i] /= (double) rtt->count();
                    }
                }
                std::discrete_distribution<size_t> distrib(upstream_weights.begin(), upstream_weights.end());
                size_t selected_idx = distrib(m_random_engine);
                last_result = co_await do_upstream_exchange(upstreams_to_query[selected_idx], request, info, 2 * max_rtt);
                if (guard.expired()) {
                    co_return {make_error(DnsError::AE_SHUTTING_DOWN), nullptr};
                }
                if (last_result->result.has_value()) {
                    co_return std::move(*last_result);
                }
                if (last_result->result.error()->value() == DnsError::AE_TIMED_OUT) {
                    // If timed out, do not try all upstreams but give a chance to fallbacks.
                    break;
                }
                // Disqualify the selected upstream and select a new one.
                std::swap(upstreams_to_query[selected_idx], upstreams_to_query.back());
                std::swap(upstream_weights[selected_idx], upstream_weights.back());
                upstreams_to_query.pop_back();
                upstream_weights.pop_back();
            }
        }
    }
    if (m_settings->enable_fallback_on_upstreams_failure && !m_fallbacks.empty()) {
        auto [fallbacks, fallbacks_max_rtt, _] = collect_upstreams(m_fallbacks, true);
        co_return co_await do_parallel_exchange(fallbacks, request, info, 2 * fallbacks_max_rtt, /*wait_all*/ true);
    }
    if (last_result) {
        assert(last_result->result.has_error());
        co_return std::move(*last_result);
    } else {
        co_return UpstreamExchangeResult{
                .result = make_error(DnsError::AE_INTERNAL_ERROR, "No upstreams have been asked"),
        };
    }
}

coro::Task<void> DnsForwarder::optimistic_cache_background_resolve(ldns_pkt_ptr req, std::string normalized_domain) {
    dbglog_id(m_log, req.get(), "Starting async upstream exchange for {}", normalized_domain);
    std::weak_ptr<bool> guard = m_shutdown_guard;
    auto [res, upstream] = co_await do_upstreams_exchange(normalized_domain, req.get(), false);
    if (guard.expired()) {
        co_return;
    }
    if (res.has_error()) {
        dbglog_id(
                m_log, req.get(), "Async upstream exchange failed, removing entry from cache: {}", res.error()->str());
        m_response_cache.erase(req.get());
    } else {
        log_packet(m_log, res->get(), "Async upstream exchange result");
        m_response_cache.put(req.get(), std::move(res.value()), upstream->options().id);
    }
    co_return;
}

bool DnsForwarder::finalize_dnssec_log_logic(ldns_pkt *response, bool is_our_do_bit) {
    bool server_uses_dnssec = false;

    if (m_settings->enable_dnssec_ok) {
        server_uses_dnssec = ldns_dnssec_pkt_has_rrsigs(response);
        tracelog(m_log, "Server uses DNSSEC: {}", server_uses_dnssec ? "YES" : "NO");
        if (is_our_do_bit && DnssecHelpers::scrub_dnssec_rrs(response)) {
            log_packet(m_log, response, "DNSSEC-scrubbed response");
        }
    }

    return server_uses_dnssec;
}

// Return true if request matches any rule in the fallback filter
bool DnsForwarder::apply_fallback_filter(std::string_view hostname, const ldns_pkt *request) {
    if (!m_fallback_filter_handle) {
        return false;
    }
    auto rules = m_filter.match(
            m_fallback_filter_handle, {hostname, ldns_rr_get_type(ldns_rr_list_rr(ldns_pkt_question(request), 0))});
    if (!rules.empty()) {
        dbglog_fid(m_log, request, "{} matches fallback filter rule: {}", hostname, rules[0].text);
        return true;
    }
    return false;
}

coro::Task<Uint8Vector> DnsForwarder::handle_message(Uint8View message, const DnsMessageInfo *info) {
    std::weak_ptr<bool> guard = m_shutdown_guard;
    // Move to EventLoop
    co_await m_loop->co_submit();
    if (guard.expired()) {
        co_return {};
    }

    if (message.size() < LDNS_HEADER_SIZE) {
        dbglog(m_log, "Not responding to malformed message");
        co_return {};
    }

    uint16_t pkt_id = read_uint16_be(message);

    DnsRequestProcessedEvent event;
    ldns_pkt *request_naked;
    ldns_status status = ldns_wire2pkt(&request_naked, message.data(), message.size());
    if (status != LDNS_STATUS_OK) {
        dbglog(m_log, "Failed to parse payload: {} ({})", ldns_get_errorstr_by_id(status),
                magic_enum::enum_name(status));
        finalize_processed_event(event, nullptr, nullptr, nullptr, std::nullopt,
                make_error(DnsError::AE_DECODE_ERROR,
                        AG_FMT("{} ({})", ldns_get_errorstr_by_id(status), magic_enum::enum_name(status))));
        ldns_pkt_ptr response{ResponseHelpers::create_formerr_response(pkt_id)};
        log_packet(m_log, response.get(), "Format error response");
        co_return transform_response_to_raw_data(response.get());
    }
    ldns_pkt_ptr request{std::exchange(request_naked, nullptr)};

    // If there's enough info, register this request
    bool retransmitted = false;
    bool retransmission_handling =
            m_settings->enable_retransmission_handling && info && !info->transparent && info->proto == utils::TP_UDP;
    if (retransmission_handling) {
        if (m_retransmission_detector.register_packet(pkt_id, info->peername) > 1) {
            dbglog(m_log, "Detected retransmitted request [{}] from {}", pkt_id, info->peername.str());
            retransmitted = true;
        }
    }

    Uint8Vector result = co_await this->handle_message_with_timeout(
            std::move(request), info ? std::make_optional(*info) : std::nullopt, retransmitted);
    if (guard.expired()) {
        co_return {};
    }

    if (retransmission_handling) {
        m_retransmission_detector.deregister_packet(pkt_id, info->peername);
    }

    co_return result;
}

coro::Task<Uint8Vector> DnsForwarder::handle_message_with_timeout(
        ldns_pkt_ptr request, std::optional<DnsMessageInfo> info, bool fallback_only) {
    DnsRequestProcessedEvent servfail_event;
    ldns_pkt_ptr servfail_response;
    uint16_t packet_id = ldns_pkt_id(request.get());
    if (m_settings->enable_servfail_on_upstreams_failure) {
        servfail_response.reset(ResponseHelpers::create_servfail_response(request.get()));
        finalize_processed_event(servfail_event, request.get(), servfail_response.get(), nullptr, std::nullopt);
    }
    Millis timeout = m_settings->upstream_timeout.count() > 0
                     ? m_settings->upstream_timeout : UpstreamFactory::DEFAULT_TIMEOUT;
    auto handle_message_aw = handle_message_internal(std::move(request), std::move(info), fallback_only);
    auto timeout_aw = [](EventLoop &loop, Millis timeout) -> coro::Task<HandleMessageResult> {
        co_await loop.co_sleep(timeout);
        co_return {.timed_out = true};
    }(*m_loop, timeout);
    std::weak_ptr<bool> guard = m_shutdown_guard;
    auto result = co_await parallel::any_of<HandleMessageResult>(handle_message_aw, timeout_aw);
    if (guard.expired()) {
        co_return {};
    }
    if (result.timed_out) {
        dbglog(m_log, "[{}] Request timed out", packet_id);
        if (m_settings->enable_servfail_on_upstreams_failure) {
            log_packet(m_log, servfail_response.get(), "Server failure response");
            if (m_events->on_request_processed) {
                servfail_event.elapsed = timeout.count();
                m_events->on_request_processed(servfail_event);
            }
            co_return transform_response_to_raw_data(servfail_response.get());
        }
        co_return {};
    }
    if (m_events->on_request_processed
            && ag::dns::is_response({result.response_wire.data(), result.response_wire.size()})) {
        m_events->on_request_processed(result.event);
    }
    co_return std::move(result.response_wire);
}

// Truncate response, if needed
void DnsForwarder::truncate_response(ldns_pkt *response, const ldns_pkt *request, const DnsMessageInfo *info) {
    if (info && info->proto == utils::TP_UDP && !info->transparent) {
        size_t max_size = ldns_pkt_edns(request) ? ldns_pkt_edns_udp_size(request) : 512;
        bool truncated = dns::ldns_pkt_truncate(response, max_size);
        if (truncated && m_log.is_enabled(ag::LogLevel::LOG_LEVEL_DEBUG)) {
            log_packet(m_log, response,
                    AG_FMT("Truncated response (edns: {}, max size: {})", ldns_pkt_edns(request), max_size));
        }
    }
}

} // namespace ag::dns
