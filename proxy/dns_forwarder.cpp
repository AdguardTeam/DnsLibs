#include <cassert>
#include <cstring>
#include <ldns/ldns.h>
#include <string>
#include <thread>

#include "common/cache.h"
#include "common/utils.h"
#include "dns/net/application_verifier.h"
#include "dns/net/default_verifier.h"
#include "dns/proxy/dnsproxy.h"

#include "dns64.h"
#include "dns_forwarder.h"
#include "dns_forwarder_utils.h"
#include "dns_truncate.h"
#include "dnssec_ok.h"
#include "ech.h"
#include "proxy_bootstrapper.h"
#include "response_cache.h"
#include "response_helpers.h"
#include "retransmission_detector.h"

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
static std::tuple<DnsFilter::EngineParams, ErrString> make_fallback_filter_params(
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
    return {DnsFilter::EngineParams{.filters = {{.data = std::move(flt_data), .in_memory = true}}}, std::nullopt};
}

// info not nullptr when logging incoming packet, nullptr for outgoing packets
static void log_packet(
        const Logger &log, const ldns_pkt *packet, std::string_view pkt_name, const DnsMessageInfo *info = nullptr) {
    if (!log.is_enabled(LogLevel::LOG_LEVEL_DEBUG)) {
        return;
    }

    ldns_buffer *str_dns = ldns_buffer_new(LDNS_MAX_PACKETLEN);
    ldns_status status = ldns_pkt2buffer_str(str_dns, packet);
    if (status != LDNS_STATUS_OK) {
        dbglog_id(log, packet, "Failed to print {}: {} ({})", pkt_name, ldns_get_errorstr_by_id(status), status);
    } else if (info) {
        dbglog_id(log, packet, "{} from {} over {}:\n{}", pkt_name, info->peername.str(),
                magic_enum::enum_name<utils::TransportProtocol>(info->proto), (char *) ldns_buffer_begin(str_dns));
    } else {
        dbglog_id(log, packet, "{}:\n{}", pkt_name, (char *) ldns_buffer_begin(str_dns));
    }
    ldns_buffer_free(str_dns);
}

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
        ErrString error) const {
    if (request != nullptr) {
        const ldns_rr *question = ldns_rr_list_rr(ldns_pkt_question(request), 0);
        char *type = ldns_rr_type2str(ldns_rr_get_type(question));
        event.type = type;
        free(type);
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

    if (error.has_value()) {
        event.error = std::move(error.value());
    } else {
        event.error.clear();
    }

    event.elapsed = duration_cast<Millis>(SystemClock::now().time_since_epoch()).count() - event.start_time;
    if (m_events->on_request_processed != nullptr) {
        m_events->on_request_processed(event);
    }
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

static coro::Task<void> discover_dns64_prefixes(std::vector<UpstreamOptions> uss,
        std::shared_ptr<SocketFactory> socket_factory, dns64::StatePtr state, Logger logger, EventLoop &loop,
        uint32_t max_tries, Millis wait_time, std::weak_ptr<bool> shutdown_guard);

std::pair<bool, ErrString> DnsForwarder::init(
        EventLoopPtr loop, const DnsProxySettings &settings, const DnsProxyEvents &events) {
    m_log = ag::Logger{"DNS forwarder"};
    m_loop = std::move(loop);
    m_shutdown_guard = std::make_shared<bool>(true);
    infolog(m_log, "Initializing forwarder...");

    m_settings = &settings;
    m_events = &events;

    if (!settings.custom_blocking_ipv4.empty() && !utils::is_valid_ip4(settings.custom_blocking_ipv4)) {
        auto err = AG_FMT("Invalid custom blocking IPv4 address: {}", settings.custom_blocking_ipv4);
        errlog(m_log, "{}", err);
        this->deinit();
        return {false, std::move(err)};
    }
    if (!settings.custom_blocking_ipv6.empty() && !utils::is_valid_ip6(settings.custom_blocking_ipv6)) {
        auto err = AG_FMT("Invalid custom blocking IPv6 address: {}", settings.custom_blocking_ipv6);
        errlog(m_log, "{}", err);
        this->deinit();
        return {false, std::move(err)};
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
    UpstreamFactory us_factory({*m_loop, m_socket_factory.get(), m_settings->ipv6_available});
    m_upstreams.reserve(settings.upstreams.size());
    m_fallbacks.reserve(settings.fallbacks.size());
    for (const UpstreamOptions &options : settings.upstreams) {
        infolog(m_log, "Initializing upstream {}...", options.address);
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
    if (m_upstreams.empty() && m_fallbacks.empty()) {
        constexpr auto err = "Failed to initialize any upstream";
        errlog(m_log, "{}", err);
        this->deinit();
        return {false, err};
    }
    infolog(m_log, "Upstreams initialized");

    infolog(m_log, "Initializing the filtering module...");
    auto [handle, err_or_warn] = m_filter.create(settings.filter_params);
    if (!handle) {
        errlog(m_log, "Failed to initialize the filtering module");
        this->deinit();
        return {false, std::move(err_or_warn)};
    }
    m_filter_handle = handle;
    if (err_or_warn) {
        warnlog(m_log, "Filtering module initialized with warnings:\n{}", *err_or_warn);
    } else {
        infolog(m_log, "Filtering module initialized");
    }

    if (!settings.fallback_domains.empty()) {
        infolog(m_log, "Initializing the fallback filter...");
        auto [params, bad_pattern] = make_fallback_filter_params(settings.fallback_domains, m_log);
        if (bad_pattern) {
            errlog(m_log, "Failed to initialize the fallback filter, bad fallback domain: {}", *bad_pattern);
            this->deinit();
            return {false, std::move(bad_pattern)};
        }
        auto [handle, err_or_warn] = m_filter.create(params);
        if (err_or_warn) { // Fallback filter must initialize cleanly, warnings are errors
            errlog(m_log, "Failed to initialize the fallback filter: {}", *err_or_warn);
            this->deinit();
            return {false, std::move(err_or_warn)};
        }
        m_fallback_filter_handle = handle;
    }

    m_dns64_state = std::make_shared<dns64::State>();
    if (settings.dns64.has_value()) {
        infolog(m_log, "DNS64 discovery is enabled");
        coro::run_detached(discover_dns64_prefixes(settings.dns64->upstreams, m_socket_factory, m_dns64_state, m_log,
                *m_loop, settings.dns64->max_tries, settings.dns64->wait_time, m_shutdown_guard));
    }

    m_response_cache.set_capacity(m_settings->dns_cache_size);

    infolog(m_log, "Forwarder initialized");
    return {true, std::move(err_or_warn)};
}

static coro::Task<void> discover_dns64_prefixes(std::vector<UpstreamOptions> uss,
        std::shared_ptr<SocketFactory> socket_factory, dns64::StatePtr state, Logger logger, EventLoop &loop,
        uint32_t max_tries, Millis wait_time, std::weak_ptr<bool> shutdown_guard) {
    co_await loop.co_submit();
    UpstreamFactory us_factory({.loop = loop, .socket_factory = socket_factory.get()});
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
                    dbglog(logger, "DNS64: failed to create DNS64 upstream: {}", upstream_result.error()->str());
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
                dbglog(logger, "DNS64: error discovering prefixes:\n{}", result.error()->str());
                continue;
            }

            if (result->empty()) {
                dbglog(logger, "DNS64: no prefixes discovered, retrying");
                continue;
            }

            state->prefixes = std::move(result.value());

            infolog(logger, "DNS64 prefixes discovered: {}", state->prefixes.size());
            co_return;
        }
    }

    dbglog(logger, "DNS64: failed to discover any prefixes");
}

void DnsForwarder::deinit() {
    infolog(m_log, "Deinitializing...");

    m_settings = nullptr;
    m_shutdown_guard.reset();

    infolog(m_log, "Destroying upstreams...");
    m_upstreams.clear();
    infolog(m_log, "Done");

    infolog(m_log, "Destroying fallback upstreams...");
    m_fallbacks.clear();
    infolog(m_log, "Done");

    infolog(m_log, "Destroying DNS64 state...");
    if (m_dns64_state) {
        m_dns64_state->discovering_upstream.reset();
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

coro::Task<Uint8Vector> DnsForwarder::handle_message_internal(
        Uint8View message, const DnsMessageInfo *info, bool fallback_only, uint16_t pkt_id) {
    std::weak_ptr<bool> guard = m_shutdown_guard;
    DnsRequestProcessedEvent event = {};
    event.start_time = duration_cast<Millis>(SystemClock::now().time_since_epoch()).count();

    ldns_pkt *request;
    ldns_status status = ldns_wire2pkt(&request, message.data(), message.length());
    if (status != LDNS_STATUS_OK) {
        std::string err = AG_FMT("Failed to parse payload: {} ({})", ldns_get_errorstr_by_id(status), status);
        dbglog(m_log, "{}", err);
        finalize_processed_event(event, nullptr, nullptr, nullptr, std::nullopt, std::move(err));
        ldns_pkt_ptr response{ResponseHelpers::create_formerr_response(pkt_id)};
        log_packet(m_log, response.get(), "Format error response");
        co_return transform_response_to_raw_data(response.get());
    }

    ldns_pkt_ptr req_holder = ldns_pkt_ptr(request);
    log_packet(m_log, request, "Client request", info);

    const ldns_rr *question = ldns_rr_list_rr(ldns_pkt_question(request), 0);
    if (question == nullptr) {
        std::string err = "Message has no question section";
        dbglog_fid(m_log, request, "{}", err);
        ldns_pkt_ptr response{ResponseHelpers::create_servfail_response(request)};
        log_packet(m_log, response.get(), "Server failure response");
        finalize_processed_event(event, nullptr, response.get(), nullptr, std::nullopt, std::move(err));
        Uint8Vector raw_response = transform_response_to_raw_data(response.get());
        co_return raw_response;
    }

    auto domain = AllocatedPtr<char>(ldns_rdf2str(ldns_rr_owner(question)));
    event.domain = domain.get();

    std::string_view normalized_domain = domain.get();
    if (ldns_dname_str_absolute(domain.get())) {
        normalized_domain.remove_suffix(1); // drop trailing dot
    }

    ResponseCache::Result cached = m_response_cache.get(request);

    if (cached.response && (!cached.expired || m_settings->optimistic_cache)) {
        log_packet(m_log, cached.response.get(), "Cached response");
        event.cache_hit = true;
        truncate_response(cached.response.get(), request, info);
        finalize_processed_event(event, request, cached.response.get(), nullptr, cached.upstream_id, std::nullopt);
        Uint8Vector raw_response = transform_response_to_raw_data(cached.response.get());
        if (cached.expired) {
            assert(m_settings->optimistic_cache);
            this->optimistic_cache_background_resolve(std::move(req_holder), std::string{normalized_domain})
                    .run_detached();
        }
        co_return raw_response;
    }

    const ldns_rr_type type = ldns_rr_get_type(question);

    // disable Mozilla DoH
    if ((type == LDNS_RR_TYPE_A || type == LDNS_RR_TYPE_AAAA) && 0 == strcmp(domain.get(), MOZILLA_DOH_HOST.data())) {
        ldns_pkt_ptr response{ResponseHelpers::create_nxdomain_response(request, m_settings)};
        log_packet(m_log, response.get(), "Mozilla DOH blocking response");
        Uint8Vector raw_response = transform_response_to_raw_data(response.get());
        finalize_processed_event(event, request, response.get(), nullptr, std::nullopt, std::nullopt);
        co_return raw_response;
    }

    tracelog_fid(m_log, request, "Query domain: {}", normalized_domain);

    std::vector<DnsFilter::Rule> effective_rules;

    // IPv6 blocking
    if (m_settings->block_ipv6 && LDNS_RR_TYPE_AAAA == type) {
        ldns_pkt_rcode rc = LDNS_RCODE_NOERROR;
        auto raw_blocking_response = co_await apply_filter(
                {
                        .domain = normalized_domain,
                        .rr_type = question_rr_type(request),
                },
                request, nullptr, event, effective_rules, fallback_only, false, &rc);
        if (!raw_blocking_response || rc == LDNS_RCODE_NOERROR) {
            dbglog_fid(m_log, request, "AAAA DNS query blocked because IPv6 blocking is enabled");
            ldns_pkt_ptr response{ResponseHelpers::create_soa_response(request, m_settings, SOA_RETRY_IPV6_BLOCK)};
            log_packet(m_log, response.get(), "IPv6 blocking response");
            co_return transform_response_to_raw_data(response.get());
        }
        co_return *raw_blocking_response;
    }

    if (auto raw_blocking_response = co_await apply_filter(
                {
                        .domain = normalized_domain,
                        .rr_type = question_rr_type(request),
                },
                request, nullptr, event, effective_rules, fallback_only)) {
        co_return *raw_blocking_response;
    }

    bool is_our_do_bit = m_settings->enable_dnssec_ok && DnssecHelpers::set_do_bit(request);

    // If this is a retransmitted request, use fallback upstreams only
    auto [response, selected_upstream] = co_await do_upstream_exchange(normalized_domain, request, fallback_only, info);
    if (guard.expired()) {
        co_return {};
    }

    if (!response) {
        auto err = response.error();
        response = ldns_pkt_ptr{ResponseHelpers::create_servfail_response(request)};
        log_packet(m_log, response->get(), "Server failure response");
        Uint8Vector raw_response = transform_response_to_raw_data(response->get());
        finalize_processed_event(event, request, response->get(), nullptr,
                std::make_optional(selected_upstream->options().id), err->str());
        co_return raw_response;
    }

    log_packet(m_log, response->get(), AG_FMT("Upstream ({}) response", selected_upstream->options().address).c_str());

    event.dnssec = finalize_dnssec_log_logic(response->get(), is_our_do_bit);

    const auto ancount = ldns_pkt_ancount(response->get());
    const auto rcode = ldns_pkt_get_rcode(response->get());

    if (LDNS_RCODE_NOERROR == rcode) {
        for (size_t i = 0; i < ancount; ++i) {
            // CNAME response blocking
            auto rr = ldns_rr_list_rr(ldns_pkt_answer(response->get()), i);
            if (ldns_rr_get_type(rr) == LDNS_RR_TYPE_CNAME) {
                if (auto raw_response = co_await apply_cname_filter(
                            rr, request, response->get(), event, effective_rules, fallback_only)) {
                    co_return *raw_response;
                }
            }
            // IP response blocking
            if (ldns_rr_get_type(rr) == LDNS_RR_TYPE_A || ldns_rr_get_type(rr) == LDNS_RR_TYPE_AAAA) {
                if (auto raw_response = co_await apply_ip_filter(
                            rr, request, response->get(), event, effective_rules, fallback_only)) {
                    co_return *raw_response;
                }
            }
        }

        // DNS64 synthesis
        if (m_settings->dns64.has_value() && LDNS_RR_TYPE_AAAA == type) {
            bool has_aaaa = false;
            for (size_t i = 0; i < ancount; ++i) {
                auto rr = ldns_rr_list_rr(ldns_pkt_answer(response->get()), i);
                if (ldns_rr_get_type(rr) == LDNS_RR_TYPE_AAAA) {
                    has_aaaa = true;
                }
            }
            if (!has_aaaa) {
                if (auto synth_response = co_await try_dns64_aaaa_synthesis(selected_upstream, req_holder)) {
                    response = std::move(synth_response);
                    log_packet(m_log, response->get(), "DNS64 synthesized response");
                }
            }
        }

        if (m_settings->block_ech) {
            if (EchHelpers::remove_ech_svcparam(response->get())) {
                dbglog_fid(m_log, response->get(), "Removed ECH parameters from SVCB/HTTPS RR");
            }
        }
    }

    truncate_response(response->get(), request, info);
    Uint8Vector raw_response = transform_response_to_raw_data(response->get());
    event.bytes_sent = message.size();
    event.bytes_received = raw_response.size();
    finalize_processed_event(event, request, response->get(), nullptr, selected_upstream->options().id, std::nullopt);
    m_response_cache.put(req_holder.get(), std::move(response.value()), selected_upstream->options().id);
    co_return raw_response;
}

coro::Task<std::optional<Uint8Vector>> DnsForwarder::apply_cname_filter(const ldns_rr *cname_rr,
        const ldns_pkt *request, const ldns_pkt *response, DnsRequestProcessedEvent &event,
        std::vector<DnsFilter::Rule> &last_effective_rules, bool fallback_only) {

    assert(ldns_rr_get_type(cname_rr) == LDNS_RR_TYPE_CNAME);

    auto rdf = ldns_rr_rdf(cname_rr, 0);
    if (!rdf) {
        co_return std::nullopt;
    }

    AllocatedPtr<char> cname_ptr(ldns_rdf2str(rdf));
    if (!cname_ptr) {
        co_return std::nullopt;
    }

    std::string_view cname = cname_ptr.get();
    if (ldns_dname_str_absolute(cname_ptr.get())) {
        cname.remove_suffix(1); // drop trailing dot
    }

    tracelog_fid(m_log, response, "Response CNAME: {}", cname);

    co_return co_await apply_filter(
            {
                    .domain = cname,
                    .rr_type = LDNS_RR_TYPE_CNAME,
            },
            request, response, event, last_effective_rules, fallback_only);
}

coro::Task<std::optional<Uint8Vector>> DnsForwarder::apply_ip_filter(const ldns_rr *rr, const ldns_pkt *request,
        const ldns_pkt *response, DnsRequestProcessedEvent &event, std::vector<DnsFilter::Rule> &last_effective_rules,
        bool fallback_only) {
    assert(ldns_rr_get_type(rr) == LDNS_RR_TYPE_A || ldns_rr_get_type(rr) == LDNS_RR_TYPE_AAAA);

    auto rdf = ldns_rr_rdf(rr, 0);
    if (!rdf || (ldns_rdf_size(rdf) != IPV4_ADDRESS_SIZE && ldns_rdf_size(rdf) != IPV6_ADDRESS_SIZE)) {
        co_return std::nullopt;
    }
    Uint8View addr{ldns_rdf_data(rdf), ldns_rdf_size(rdf)};
    std::string addr_str = ag::utils::addr_to_str(addr);

    tracelog_fid(m_log, response, "Response IP: {}", addr_str);

    co_return co_await apply_filter({.domain = addr_str, .rr_type = ldns_rr_get_type(rr)}, request, response, event,
            last_effective_rules, fallback_only);
}

coro::Task<std::optional<Uint8Vector>> DnsForwarder::apply_filter(DnsFilter::MatchParam match, const ldns_pkt *request,
        const ldns_pkt *original_response, DnsRequestProcessedEvent &event,
        std::vector<DnsFilter::Rule> &last_effective_rules, bool fallback_only, bool fire_event,
        ldns_pkt_rcode *out_rcode) {

    auto rules = m_filter.match(m_filter_handle, match);
    for (const DnsFilter::Rule &rule : rules) {
        tracelog_fid(m_log, request, "Matched rule: {}", rule.text);
    }
    rules.insert(rules.end(), std::make_move_iterator(last_effective_rules.begin()),
            std::make_move_iterator(last_effective_rules.end()));
    last_effective_rules.clear();

    auto effective_rules = DnsFilter::get_effective_rules(rules);

    std::optional<DnsFilter::ApplyDnsrewriteResult::RewriteInfo> rewrite_info;
    if (!effective_rules.dnsrewrite.empty()) {
        auto rewrite_result = DnsFilter::apply_dnsrewrite_rules(effective_rules.dnsrewrite);
        for (const DnsFilter::Rule *rule : rewrite_result.rules) {
            tracelog_fid(m_log, request, "Applied $dnsrewrite: {}", rule->text);
        }
        effective_rules.dnsrewrite = std::move(rewrite_result.rules);
        rewrite_info = std::move(rewrite_result.rewritten_info);
    }

    last_effective_rules.reserve(effective_rules.dnsrewrite.size() + effective_rules.leftovers.size());
    std::transform(effective_rules.dnsrewrite.begin(), effective_rules.dnsrewrite.end(),
            std::back_inserter(last_effective_rules), [](const DnsFilter::Rule *r) {
                return *r;
            });
    std::transform(effective_rules.leftovers.begin(), effective_rules.leftovers.end(),
            std::back_inserter(last_effective_rules), [](const DnsFilter::Rule *r) {
                return *r;
            });

    event_append_rules(event, effective_rules.dnsrewrite);
    if (!rewrite_info.has_value()) {
        event_append_rules(event, effective_rules.leftovers);
    }

    if (const DnsFilter::AdblockRuleInfo * content; !rewrite_info.has_value()
            && (effective_rules.leftovers.empty()
                    || (nullptr
                                    != (content = std::get_if<DnsFilter::AdblockRuleInfo>(
                                                &effective_rules.leftovers[0]->content))
                            && content->props.test(DnsFilter::DARP_EXCEPTION)))) {
        co_return std::nullopt;
    }

    if (effective_rules.dnsrewrite.empty()) {
        dbglog_fid(m_log, request, "DNS query blocked by rule: {}", effective_rules.leftovers[0]->text);
    } else {
        dbglog_fid(
                m_log, request, "DNS query blocked by $dnsrewrite rule(s): num={}", effective_rules.dnsrewrite.size());
    }

    if (rewrite_info.has_value() && rewrite_info->cname.has_value()) {
        ldns_pkt_ptr rewritten_request{ldns_pkt_clone(request)};
        ldns_rr *question = ldns_rr_list_rr(ldns_pkt_question(rewritten_request.get()), 0);
        ldns_rdf_deep_free(ldns_rr_owner(question));
        ldns_rr_set_owner(question, ldns_dname_new_frm_str(rewrite_info->cname->c_str()));
        std::string_view rwr_cname = *rewrite_info->cname;
        if (rwr_cname.back() == '.') {
            rwr_cname.remove_suffix(1);
        }

        log_packet(m_log, rewritten_request.get(), "Rewritten cname request");

        auto [response, _] = co_await this->do_upstream_exchange(rwr_cname, rewritten_request.get(), fallback_only);
        if (!response) {
            dbglog_id(m_log, rewritten_request.get(), "Failed to resolve rewritten cname: {}", response.error()->str());
            co_return std::nullopt;
        }

        log_packet(m_log, rewritten_request.get(), "Rewritten cname response");
        for (size_t i = 0; i < ldns_pkt_ancount(response->get()); ++i) {
            ldns_rr *rr = ldns_rr_list_rr(ldns_pkt_answer(response->get()), i);
            if (ldns_rr_get_type(rr) == ldns_rr_get_type(question)) {
                ldns_rdf_deep_free(ldns_rr_owner(rr));
                ldns_rr_set_owner(rr, nullptr);
                rewrite_info->rrs.emplace_back(ldns_rr_clone(rr));
            }
        }
    }

    ldns_pkt_ptr response{ResponseHelpers::create_blocking_response(
            request, m_settings, effective_rules.leftovers, std::move(rewrite_info))};
    log_packet(m_log, response.get(), "Rule blocked response");
    if (out_rcode) {
        *out_rcode = ldns_pkt_get_rcode(response.get());
    }
    Uint8Vector raw_response = transform_response_to_raw_data(response.get());
    if (fire_event) {
        finalize_processed_event(event, request, response.get(), original_response, std::nullopt, std::nullopt);
    }

    co_return raw_response;
}

#ifdef ANDROID
[[clang::optnone]]
#endif
coro::Task<UpstreamExchangeResult> DnsForwarder::do_upstream_exchange(
        std::string_view normalized_domain, ldns_pkt *request, bool fallback_only, const DnsMessageInfo *info) {
    bool use_only_fallbacks =
            !m_fallbacks.empty() && (fallback_only || apply_fallback_filter(normalized_domain, request));
    std::vector<std::vector<UpstreamPtr> *> v;
    if (!use_only_fallbacks) {
        v.emplace_back(&m_upstreams);
    }
    v.emplace_back(&m_fallbacks);

    assert(m_upstreams.size() + m_fallbacks.size());
    Upstream *cur_upstream;
    Error<DnsError> err;
    std::weak_ptr<bool> guard = m_shutdown_guard;
    for (auto upstream_vector : v) {
        std::vector<Upstream *> sorted_upstreams;
        sorted_upstreams.reserve(upstream_vector->size());
        for (auto &u : *upstream_vector) {
            sorted_upstreams.push_back(u.get());
        }
        std::sort(sorted_upstreams.begin(), sorted_upstreams.end(), [](Upstream *a, Upstream *b) {
            return (a->rtt() < b->rtt());
        });

        for (auto &sorted_upstream : sorted_upstreams) {
            cur_upstream = sorted_upstream;
            std::string address = cur_upstream->options().address;

            ag::utils::Timer t;
            tracelog_id(m_log, request, "Upstream ({}) is starting an exchange", address);
            Upstream::ExchangeResult result = co_await cur_upstream->exchange(request, info);
            tracelog_id(m_log, request, "Upstream's ({}) exchanging is done", address);
            if (guard.expired()) {
                co_return {make_error(DE_SHUTTING_DOWN), nullptr};
            }
            cur_upstream->adjust_rtt(t.elapsed<Millis>());

            if (!result.has_error()) {
                co_return {std::move(result.value()), cur_upstream};
            } else if (result.error()->value() != DE_TIMED_OUT && result.error()->value() != DE_SHUTTING_DOWN) {
                // https://github.com/AdguardTeam/DnsLibs/issues/86
                Upstream::ExchangeResult retry_result = co_await cur_upstream->exchange(request, info);
                if (guard.expired()) {
                    co_return {make_error(DE_SHUTTING_DOWN), nullptr};
                }
                if (!retry_result.has_error()) {
                    co_return {std::move(retry_result.value()), cur_upstream};
                }
                err = make_error(DE_NESTED_DNS_ERROR,
                        AG_FMT("Upstream ({}) exchange failed: first reason is:\n{}\nsecond reason is:", address,
                                result.error()->str()),
                        retry_result.error());
                dbglog_id(m_log, request, "{}", err->str());
            } else {
                std::string error_str = result.error()->str();
                std::string address_copy = address;
                std::string message = AG_FMT("Upstream ({}) exchange failed: {}", address_copy, error_str);
                err = make_error(DE_NESTED_DNS_ERROR, message);
                dbglog_id(m_log, request, "{}", err->str());
            }
        }
    }
    co_return {err, cur_upstream};
}

coro::Task<void> DnsForwarder::optimistic_cache_background_resolve(ldns_pkt_ptr req, std::string normalized_domain) {
    dbglog_id(m_log, req.get(), "Starting async upstream exchange for {}", normalized_domain);
    std::weak_ptr<bool> guard = m_shutdown_guard;
    auto [res, upstream] = co_await do_upstream_exchange(normalized_domain, req.get(), false);
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

    // If there's enough info, register this request
    bool retransmitted = false;
    bool retransmission_handling = m_settings->enable_retransmission_handling && info && info->proto == utils::TP_UDP;
    if (retransmission_handling) {
        if (m_retransmission_detector.register_packet(pkt_id, info->peername) > 1) {
            dbglog(m_log, "Detected retransmitted request [{}] from {}", pkt_id, info->peername.str());
            retransmitted = true;
        }
    }

    Uint8Vector result = co_await this->handle_message_internal(message, info, retransmitted, pkt_id);
    if (guard.expired()) {
        co_return {};
    }

    if (retransmission_handling) {
        m_retransmission_detector.deregister_packet(pkt_id, info->peername);
    }

    co_return result;
}

// Truncate response, if needed
void DnsForwarder::truncate_response(ldns_pkt *response, const ldns_pkt *request, const DnsMessageInfo *info) {
    if (info && info->proto == utils::TP_UDP) {
        size_t max_size = ldns_pkt_edns(request) ? ldns_pkt_edns_udp_size(request) : 512;
        bool truncated = dns::ldns_pkt_truncate(response, max_size);
        if (truncated && m_log.is_enabled(ag::LogLevel::LOG_LEVEL_DEBUG)) {
            log_packet(m_log, response,
                    AG_FMT("Truncated response (edns: {}, max size: {})", ldns_pkt_edns(request), max_size));
        }
    }
}

} // namespace ag::dns
