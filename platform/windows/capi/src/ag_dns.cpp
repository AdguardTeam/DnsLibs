#include <ag_dns.h>

#include <cstring>

#include "dns/dnsfilter/dnsfilter.h"
#include "dns/proxy/dnsproxy.h"
#include "dns/upstream/upstream_utils.h"

#ifdef _WIN32
#include <detours.h>

/**
 * Deactivated version of SetUnhandledExceptionFilter that does nothing.
 * This is needed because there are many places in runtime where SetUnhandledExceptionFilter is called.
 * @param lpTopLevelExceptionFilter Pointer to exception filter function
 * @return Pointer if success, NULL if error is occurred. This function always succeeds.
 */
static LPTOP_LEVEL_EXCEPTION_FILTER WINAPI DontSetUnhandledExceptionFilter(
        LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter) {
    // Do nothing
    return lpTopLevelExceptionFilter;
}

static void *detoursHook_SetUnhandledExceptionFilter = (void *) SetUnhandledExceptionFilter;

void ag_disable_SetUnhandledExceptionFilter(void) {
    DetourTransactionBegin();
    DetourAttach(&detoursHook_SetUnhandledExceptionFilter, (void *) DontSetUnhandledExceptionFilter);
    DetourTransactionCommit();
}

void ag_enable_SetUnhandledExceptionFilter(void) {
    DetourTransactionBegin();
    DetourDetach(&detoursHook_SetUnhandledExceptionFilter, (void *) DontSetUnhandledExceptionFilter);
    DetourTransactionCommit();
}
#endif // _WIN32

using namespace ag;
using namespace ag::dns;

static constexpr const char *AGCVR_TO_STRING[] = {
        "ERROR_OK",
        "ERROR_CREATE_CERT",
        "ERROR_ACCESS_TO_STORE",
        "ERROR_CERT_VERIFICATION",
};

static void free_upstreams(ag_upstream_options *upstreams, size_t n) {
    for (size_t i = 0; i < n; ++i) {
        ag_upstream_options &o = upstreams[i];
        std::free((void *) o.address);
        ag_buffer_free(o.resolved_ip_address);
        for (size_t j = 0; j < o.bootstrap.size; ++j) {
            ag_str_free(o.bootstrap.data[j]);
        }
        std::free(o.bootstrap.data);
    }
    std::free(upstreams);
}

static void free_settings_overrides(ag_proxy_settings_overrides *x) {
    delete x->block_ech;
}

static void free_listeners(ag_listener_settings *listeners, size_t n) {
    for (size_t i = 0; i < n; ++i) {
        ag_listener_settings &o = listeners[i];
        free_settings_overrides(&o.settings_overrides);
        std::free((void *) o.address);
    }
    std::free(listeners);
}

static void free_filters(ag_filter_params *filter_params, size_t n) {
    for (size_t i = 0; i < n; ++i) {
        std::free((void *) filter_params->data);
    }
    std::free(filter_params);
}

static char *marshal_str(const std::string &str) {
    if (str.empty()) {
        return nullptr;
    }
    return strdup(str.c_str());
}

static ag_buffer marshal_buffer(Uint8View v) {
    ag_buffer buf;
    buf.size = v.size();
    buf.data = (uint8_t *) std::malloc(buf.size);
    std::memcpy((void *) buf.data, v.data(), buf.size);
    return buf;
}

void ag_buffer_free(ag_buffer buf) {
    std::free((void *) buf.data);
}

static const char **marshal_strs(const std::vector<std::string> &strs) {
    if (strs.empty()) {
        return nullptr;
    }
    const char **c_strs = (const char **) std::malloc(strs.size() * sizeof(char *));
    for (size_t i = 0; i < strs.size(); ++i) {
        c_strs[i] = marshal_str(strs[i]);
    }
    return c_strs;
}

static ag_upstream_options marshal_upstream(const UpstreamOptions &upstream) {
    ag_upstream_options c_upstream{};

    c_upstream.address = marshal_str(upstream.address);
    c_upstream.id = upstream.id;

    if (const Ipv4Address *arr4 = std::get_if<Ipv4Address>(&upstream.resolved_server_ip)) {
        c_upstream.resolved_ip_address = marshal_buffer({arr4->data(), arr4->size()});
    } else if (const Ipv6Address *arr6 = std::get_if<Ipv6Address>(&upstream.resolved_server_ip)) {
        c_upstream.resolved_ip_address = marshal_buffer({arr6->data(), arr6->size()});
    }

    c_upstream.bootstrap.size = upstream.bootstrap.size();
    c_upstream.bootstrap.data = marshal_strs(upstream.bootstrap);

    if (const uint32_t *idx = std::get_if<uint32_t>(&upstream.outbound_interface)) {
        c_upstream.outbound_interface_index = *idx;
    }

    c_upstream.fingerprints.size = upstream.fingerprints.size();
    c_upstream.fingerprints.data = marshal_strs(upstream.fingerprints);

    return c_upstream;
}

static ag_upstream_options *marshal_upstreams(const std::vector<UpstreamOptions> &upstreams) {
    if (upstreams.empty()) {
        return nullptr;
    }
    auto *c_upstreams = (ag_upstream_options *) std::malloc(upstreams.size() * sizeof(ag_upstream_options));
    for (size_t i = 0; i < upstreams.size(); ++i) {
        c_upstreams[i] = marshal_upstream(upstreams[i]);
    }
    return c_upstreams;
}

static ag_dns64_settings *marshal_dns64(const std::optional<Dns64Settings> &dns64) {
    if (!dns64) {
        return nullptr;
    }
    auto *c_dns64 = (ag_dns64_settings *) std::malloc(sizeof(ag_dns64_settings));
    c_dns64->max_tries = dns64->max_tries;
    c_dns64->wait_time_ms = dns64->wait_time.count();
    c_dns64->upstreams.size = dns64->upstreams.size();
    c_dns64->upstreams.data = marshal_upstreams(dns64->upstreams);
    return c_dns64;
}

static void free_dns64(ag_dns64_settings *dns64) {
    if (dns64) {
        free_upstreams(dns64->upstreams.data, dns64->upstreams.size);
    }
    std::free(dns64);
}

static ag_filter_params marshal_filter_params(const DnsFilter::FilterParams &params) {
    ag_filter_params c_params{};
    c_params.data = marshal_str(params.data);
    c_params.in_memory = params.in_memory;
    c_params.id = params.id;
    return c_params;
}

static ag_filter_params *marshal_filters(const std::vector<DnsFilter::FilterParams> &filters) {
    if (filters.empty()) {
        return nullptr;
    }
    auto *c_filters = (ag_filter_params *) std::malloc(filters.size() * sizeof(ag_filter_params));
    for (size_t i = 0; i < filters.size(); ++i) {
        c_filters[i] = marshal_filter_params(filters[i]);
    }
    return c_filters;
}

static ag_filter_engine_params marshal_engine_params(const DnsFilter::EngineParams &params) {
    ag_filter_engine_params c_params{};
    c_params.filters.size = params.filters.size();
    c_params.filters.data = marshal_filters(params.filters);
    return c_params;
}

static ag_proxy_settings_overrides marshal_settings_overrides(const ProxySettingsOverrides &x) {
    ag_proxy_settings_overrides ret = {};
    if (x.block_ech.has_value()) {
        ret.block_ech = new bool(x.block_ech.value());
    }
    return ret;
}

static ag_listener_settings marshal_listener(const ListenerSettings &listener) {
    ag_listener_settings c_listener{};
    c_listener.address = marshal_str(listener.address);
    c_listener.port = listener.port;
    c_listener.protocol = (ag_listener_protocol) listener.protocol;
    c_listener.persistent = listener.persistent;
    c_listener.idle_timeout_ms = listener.idle_timeout.count();
    c_listener.settings_overrides = marshal_settings_overrides(listener.settings_overrides);
    return c_listener;
}

static ag_listener_settings *marshal_listeners(const std::vector<ListenerSettings> &listeners) {
    if (listeners.empty()) {
        return nullptr;
    }
    auto *c_listeners = (ag_listener_settings *) std::malloc(listeners.size() * sizeof(ag_listener_settings));
    for (size_t i = 0; i < listeners.size(); ++i) {
        c_listeners[i] = marshal_listener(listeners[i]);
    }
    return c_listeners;
}

static ag_outbound_proxy_settings *marshal_outbound_proxy(const std::optional<OutboundProxySettings> &outbound_proxy) {
    if (!outbound_proxy.has_value()) {
        return nullptr;
    }
    auto *c_outbound_proxy = (ag_outbound_proxy_settings *) std::malloc(sizeof(ag_outbound_proxy_settings));
    c_outbound_proxy->protocol = (ag_outbound_proxy_protocol) outbound_proxy->protocol;
    c_outbound_proxy->address = marshal_str(outbound_proxy->address);
    c_outbound_proxy->port = outbound_proxy->port;
    c_outbound_proxy->bootstrap.size = outbound_proxy->bootstrap.size();
    c_outbound_proxy->bootstrap.data = marshal_strs(outbound_proxy->bootstrap);
    if (outbound_proxy->auth_info.has_value()) {
        c_outbound_proxy->auth_info = (ag_outbound_proxy_auth_info *) std::malloc(sizeof(ag_outbound_proxy_auth_info));
        c_outbound_proxy->auth_info->username = marshal_str(outbound_proxy->auth_info->username);
        c_outbound_proxy->auth_info->password = marshal_str(outbound_proxy->auth_info->password);
    } else {
        c_outbound_proxy->auth_info = nullptr;
    }
    c_outbound_proxy->trust_any_certificate = outbound_proxy->trust_any_certificate;
    return c_outbound_proxy;
}

static void free_outbound_proxy(ag_outbound_proxy_settings *outbound_proxy) {
    if (outbound_proxy == nullptr) {
        return;
    }

    std::free((void *) outbound_proxy->address);

    for (size_t j = 0; j < outbound_proxy->bootstrap.size; ++j) {
        ag_str_free(outbound_proxy->bootstrap.data[j]);
    }
    std::free(outbound_proxy->bootstrap.data);

    if (outbound_proxy->auth_info != nullptr) {
        std::free((void *) outbound_proxy->auth_info->username);
        std::free((void *) outbound_proxy->auth_info->password);
        std::free(outbound_proxy->auth_info);
    }

    std::free(outbound_proxy);
}

static ag_dnsproxy_settings *marshal_settings(const DnsProxySettings &settings) {
    auto *c_settings = (ag_dnsproxy_settings *) std::malloc(sizeof(ag_dnsproxy_settings));

    c_settings->block_ipv6 = settings.block_ipv6;
    c_settings->ipv6_available = settings.ipv6_available;
    c_settings->dns_cache_size = settings.dns_cache_size;
    c_settings->upstream_timeout_ms = settings.upstream_timeout.count();
    c_settings->blocked_response_ttl_secs = settings.blocked_response_ttl_secs;
    c_settings->adblock_rules_blocking_mode = (ag_dnsproxy_blocking_mode) settings.adblock_rules_blocking_mode;
    c_settings->hosts_rules_blocking_mode = (ag_dnsproxy_blocking_mode) settings.hosts_rules_blocking_mode;
    c_settings->custom_blocking_ipv4 = marshal_str(settings.custom_blocking_ipv4);
    c_settings->custom_blocking_ipv6 = marshal_str(settings.custom_blocking_ipv6);
    c_settings->dns64 = marshal_dns64(settings.dns64);
    c_settings->upstreams.size = settings.upstreams.size();
    c_settings->upstreams.data = marshal_upstreams(settings.upstreams);
    c_settings->fallbacks.size = settings.fallbacks.size();
    c_settings->fallbacks.data = marshal_upstreams(settings.fallbacks);
    c_settings->fallback_domains.size = settings.fallback_domains.size();
    c_settings->fallback_domains.data = marshal_strs(settings.fallback_domains);
    c_settings->filter_params = marshal_engine_params(settings.filter_params);
    c_settings->listeners.size = settings.listeners.size();
    c_settings->listeners.data = marshal_listeners(settings.listeners);
    c_settings->outbound_proxy = marshal_outbound_proxy(settings.outbound_proxy);
    c_settings->optimistic_cache = settings.optimistic_cache;
    c_settings->enable_dnssec_ok = settings.enable_dnssec_ok;
    c_settings->enable_retransmission_handling = settings.enable_retransmission_handling;
    c_settings->block_ech = settings.block_ech;
    c_settings->enable_parallel_upstream_queries = settings.enable_parallel_upstream_queries;
    c_settings->enable_fallback_on_upstreams_failure = settings.enable_fallback_on_upstreams_failure;
    c_settings->enable_servfail_on_upstreams_failure = settings.enable_servfail_on_upstreams_failure;
    c_settings->enable_http3 = settings.enable_http3;

    return c_settings;
}

static ServerStamp marshal_stamp(const ag_dns_stamp *c_stamp) {
    ServerStamp stamp{};
    stamp.proto = (StampProtoType) c_stamp->proto;
    if (c_stamp->path) {
        stamp.path = c_stamp->path;
    }
    if (c_stamp->server_addr) {
        stamp.server_addr_str = c_stamp->server_addr;
    }
    if (c_stamp->provider_name) {
        stamp.provider_name = c_stamp->provider_name;
    }
    stamp.server_pk.assign(
            c_stamp->server_public_key.data, c_stamp->server_public_key.data + c_stamp->server_public_key.size);
    for (size_t i = 0; i < c_stamp->hashes.size; ++i) {
        const ag_buffer &hash = c_stamp->hashes.data[i];
        stamp.hashes.emplace_back(hash.data, hash.data + hash.size);
    }
    if (c_stamp->properties) {
        stamp.props = (ServerInformalProperties) *c_stamp->properties;
    }
    return stamp;
}

static DnsRequestProcessedEvent marshal_processed_event(const ag_dns_request_processed_event *c_event) {
    DnsRequestProcessedEvent event;
    event.whitelist = c_event->whitelist;
    event.cache_hit = c_event->cache_hit;
    event.dnssec = c_event->dnssec;
    event.type = c_event->type ? c_event->type : "";
    event.domain = c_event->domain ? c_event->domain : "";
    event.start_time = c_event->start_time;
    event.elapsed = c_event->elapsed;
    event.bytes_received = c_event->bytes_received;
    event.bytes_sent = c_event->bytes_sent;
    event.answer = c_event->answer ? c_event->answer : "";
    event.original_answer = c_event->original_answer ? c_event->original_answer : "";
    event.error = c_event->error ? c_event->error : "";
    event.status = c_event->status ? c_event->status : "";
    event.upstream_id = c_event->upstream_id ? std::make_optional(*c_event->upstream_id) : std::nullopt;
    for (uint32_t i = 0; i < c_event->filter_list_ids.size; ++i) {
        event.filter_list_ids.emplace_back(c_event->filter_list_ids.data[i]);
    }
    for (uint32_t i = 0; i < c_event->rules.size; ++i) {
        if (const char *rule = c_event->rules.data[i]) {
            event.rules.emplace_back(rule);
        }
    }
    return event;
}

void ag_dnsproxy_settings_free(ag_dnsproxy_settings *settings) {
    if (!settings) {
        return;
    }
    std::free((void *) settings->custom_blocking_ipv6);
    std::free((void *) settings->custom_blocking_ipv4);
    for (size_t j = 0; j < settings->fallback_domains.size; ++j) {
        ag_str_free(settings->fallback_domains.data[j]);
    }
    std::free(settings->fallback_domains.data);
    free_upstreams(settings->upstreams.data, settings->upstreams.size);
    free_upstreams(settings->fallbacks.data, settings->fallbacks.size);
    free_dns64(settings->dns64);
    free_listeners(settings->listeners.data, settings->listeners.size);
    free_filters(settings->filter_params.filters.data, settings->filter_params.filters.size);
    free_outbound_proxy(settings->outbound_proxy);
    std::free(settings);
}

static UpstreamOptions marshal_upstream(const ag_upstream_options &c_upstream) {
    UpstreamOptions upstream{};
    if (c_upstream.address) {
        upstream.address.assign(c_upstream.address);
    }
    upstream.id = c_upstream.id;
    if (c_upstream.resolved_ip_address.size == IPV4_ADDRESS_SIZE) {
        Ipv4Address arr4;
        std::memcpy(arr4.data(), c_upstream.resolved_ip_address.data, arr4.size());
        upstream.resolved_server_ip = arr4;
    } else if (c_upstream.resolved_ip_address.size == IPV6_ADDRESS_SIZE) {
        Ipv6Address arr6;
        std::memcpy(arr6.data(), c_upstream.resolved_ip_address.data, arr6.size());
        upstream.resolved_server_ip = arr6;
    }
    for (size_t i = 0; i < c_upstream.bootstrap.size; ++i) {
        upstream.bootstrap.emplace_back(c_upstream.bootstrap.data[i]);
    }
    if (c_upstream.outbound_interface_index != 0) {
        upstream.outbound_interface = c_upstream.outbound_interface_index;
    }
    for (size_t i = 0; i < c_upstream.fingerprints.size; ++i) {
        upstream.fingerprints.emplace_back(c_upstream.fingerprints.data[i]);
    }
    return upstream;
}

static std::vector<UpstreamOptions> marshal_upstreams(const ag_upstream_options *c_upstreams, size_t n) {
    std::vector<UpstreamOptions> upstreams;
    upstreams.reserve(n);
    for (size_t i = 0; i < n; ++i) {
        upstreams.emplace_back(marshal_upstream(c_upstreams[i]));
    }
    return upstreams;
}

static ProxySettingsOverrides marshal_settings_overrides(const ag_proxy_settings_overrides &x) {
    ProxySettingsOverrides ret = {};
    if (x.block_ech != nullptr) {
        ret.block_ech = *x.block_ech;
    }
    return ret;
}

static ListenerSettings marshal_listener(const ag_listener_settings &c_listener) {
    ListenerSettings listener{};
    if (c_listener.address) {
        listener.address.assign(c_listener.address);
    }
    listener.port = c_listener.port;
    listener.protocol = (utils::TransportProtocol) c_listener.protocol;
    listener.persistent = c_listener.persistent;
    listener.idle_timeout = Millis{c_listener.idle_timeout_ms};
    listener.settings_overrides = marshal_settings_overrides(c_listener.settings_overrides);
    return listener;
}

static std::vector<ListenerSettings> marshal_listeners(const ag_listener_settings *c_listeners, size_t n) {
    std::vector<ListenerSettings> listeners;
    listeners.reserve(n);
    for (size_t i = 0; i < n; ++i) {
        listeners.emplace_back(marshal_listener(c_listeners[i]));
    }
    return listeners;
}

static std::optional<OutboundProxySettings> marshal_outbound_proxy(const ag_outbound_proxy_settings *c_settings) {
    if (c_settings == nullptr) {
        return std::nullopt;
    }

    OutboundProxySettings settings = {};
    if (c_settings->address != nullptr) {
        settings.address.assign(c_settings->address);
    }
    settings.port = c_settings->port;
    settings.bootstrap.reserve(c_settings->bootstrap.size);
    for (size_t i = 0; i < c_settings->bootstrap.size; ++i) {
        settings.bootstrap.emplace_back(c_settings->bootstrap.data[i]);
    }
    if (const ag_outbound_proxy_auth_info *c_auth_info = c_settings->auth_info; c_auth_info != nullptr) {
        OutboundProxyAuthInfo &auth_info = settings.auth_info.emplace();
        if (c_auth_info->username != nullptr) {
            auth_info.username.assign(c_auth_info->username);
        }
        if (c_auth_info->password != nullptr) {
            auth_info.password.assign(c_auth_info->password);
        }
    }
    settings.trust_any_certificate = c_settings->trust_any_certificate;
    return std::move(settings);
}

static DnsFilter::FilterParams marshal_filter_params(const ag_filter_params &c_params) {
    DnsFilter::FilterParams params{};
    if (c_params.data) {
        params.data.assign(c_params.data);
    }
    params.in_memory = c_params.in_memory;
    params.id = c_params.id;
    return params;
}

static std::vector<DnsFilter::FilterParams> marshal_filters(const ag_filter_params *c_filters, size_t n) {
    std::vector<DnsFilter::FilterParams> filters;
    filters.reserve(n);
    for (size_t i = 0; i < n; ++i) {
        filters.emplace_back(marshal_filter_params(c_filters[i]));
    }
    return filters;
}

static DnsProxySettings marshal_settings(const ag_dnsproxy_settings *c_settings) {
    DnsProxySettings settings{};

    settings.block_ipv6 = c_settings->block_ipv6;
    settings.ipv6_available = c_settings->ipv6_available;
    settings.dns_cache_size = c_settings->dns_cache_size;
    settings.upstream_timeout = Millis{c_settings->upstream_timeout_ms};
    settings.blocked_response_ttl_secs = c_settings->blocked_response_ttl_secs;
    settings.adblock_rules_blocking_mode = (DnsProxyBlockingMode) c_settings->adblock_rules_blocking_mode;
    settings.hosts_rules_blocking_mode = (DnsProxyBlockingMode) c_settings->hosts_rules_blocking_mode;
    if (c_settings->custom_blocking_ipv4) {
        settings.custom_blocking_ipv4.assign(c_settings->custom_blocking_ipv4);
    }
    if (c_settings->custom_blocking_ipv6) {
        settings.custom_blocking_ipv6.assign(c_settings->custom_blocking_ipv6);
    }
    if (c_settings->dns64) {
        Dns64Settings dns64{};
        dns64.upstreams = marshal_upstreams(c_settings->dns64->upstreams.data, c_settings->dns64->upstreams.size);
        dns64.max_tries = c_settings->dns64->max_tries;
        dns64.wait_time = Millis{c_settings->dns64->wait_time_ms};
        settings.dns64 = dns64;
    }
    settings.upstreams = marshal_upstreams(c_settings->upstreams.data, c_settings->upstreams.size);
    settings.fallbacks = marshal_upstreams(c_settings->fallbacks.data, c_settings->fallbacks.size);

    for (size_t i = 0; i < c_settings->fallback_domains.size; ++i) {
        settings.fallback_domains.emplace_back(c_settings->fallback_domains.data[i]);
    }

    settings.listeners = marshal_listeners(c_settings->listeners.data, c_settings->listeners.size);
    settings.outbound_proxy = marshal_outbound_proxy(c_settings->outbound_proxy);
    settings.filter_params.filters
            = marshal_filters(c_settings->filter_params.filters.data, c_settings->filter_params.filters.size);
    settings.optimistic_cache = c_settings->optimistic_cache;
    settings.enable_dnssec_ok = c_settings->enable_dnssec_ok;
    settings.enable_retransmission_handling = c_settings->enable_retransmission_handling;
    settings.block_ech = c_settings->block_ech;
    settings.enable_parallel_upstream_queries = c_settings->enable_parallel_upstream_queries;
    settings.enable_fallback_on_upstreams_failure = c_settings->enable_fallback_on_upstreams_failure;
    settings.enable_servfail_on_upstreams_failure = c_settings->enable_servfail_on_upstreams_failure;
    settings.enable_http3 = c_settings->enable_http3;

    return settings;
}

static const char *c_str_if_not_empty(const std::string &str) {
    return str.empty() ? nullptr : str.c_str();
}

static DnsProxyEvents marshal_events(const ag_dnsproxy_events *c_events) {
    DnsProxyEvents events{};
    if (!c_events) {
        return events;
    }
    if (c_events->on_request_processed) {
        events.on_request_processed = [cb = c_events->on_request_processed](
                                              const DnsRequestProcessedEvent &event) {
            ag_dns_request_processed_event e{};

            e.whitelist = event.whitelist;
            e.cache_hit = event.cache_hit;
            e.dnssec = event.dnssec;
            e.filter_list_ids.data = event.filter_list_ids.data();
            e.filter_list_ids.size = event.filter_list_ids.size();
            e.type = c_str_if_not_empty(event.type);
            e.domain = c_str_if_not_empty(event.domain);
            e.start_time = event.start_time;
            e.elapsed = event.elapsed;
            e.bytes_received = event.bytes_received;
            e.bytes_sent = event.bytes_sent;
            e.answer = c_str_if_not_empty(event.answer);
            e.original_answer = c_str_if_not_empty(event.original_answer);
            e.error = c_str_if_not_empty(event.error);
            e.status = c_str_if_not_empty(event.status);
            e.upstream_id = event.upstream_id ? &*event.upstream_id : nullptr;

            std::vector<const char *> c_rules;
            c_rules.reserve(event.rules.size());
            std::for_each(event.rules.begin(), event.rules.end(), [&c_rules](auto &rule) {
                c_rules.push_back(rule.c_str());
            });
            e.rules.data = c_rules.data();
            e.rules.size = c_rules.size();

            cb(&e);
        };
    }
    if (c_events->on_certificate_verification) {
        events.on_certificate_verification
                = [cb = c_events->on_certificate_verification](
                          const CertificateVerificationEvent &event) -> std::optional<std::string> {
            ag_certificate_verification_event e{};

            e.certificate.size = event.certificate.size();
            e.certificate.data = (uint8_t *) event.certificate.data();

            std::vector<ag_buffer> c_buffers;
            c_buffers.reserve(event.chain.size());
            std::for_each(event.chain.begin(), event.chain.end(), [&c_buffers](auto &cert) {
                ag_buffer buf{(uint8_t *) cert.data(), (uint32_t) cert.size()};
                c_buffers.emplace_back(std::move(buf));
            });
            e.chain.size = c_buffers.size();
            e.chain.data = c_buffers.data();

            int res = cb(&e);
            if (res == AGCVR_OK) {
                return std::nullopt;
            }
            if (res >= AGCVR_COUNT || res < 0) {
                return "Unknown error";
            }
            return AGCVR_TO_STRING[res];
        };
    }
    return events;
}

ag_dnsproxy_settings *ag_dnsproxy_settings_get_default() {
    const auto &settings = DnsProxySettings::get_default();
    auto *c_settings = marshal_settings(settings);
    return c_settings;
}

ag_dnsproxy *ag_dnsproxy_init(const ag_dnsproxy_settings *c_settings, const ag_dnsproxy_events *c_events,
        ag_dnsproxy_init_result *out_result, const char **out_message) {
    auto settings = marshal_settings(c_settings);
    auto events = marshal_events(c_events);

    auto *proxy = new DnsProxy;
    auto [ret, err_or_warn] = proxy->init(settings, events);

    if (ret) {
        if (err_or_warn) {
            *out_result = (ag_dnsproxy_init_result) err_or_warn->value();
            *out_message = strdup(err_or_warn->str().c_str());
        } else {
            *out_result = AGDPIR_OK;
        }
        return (void *) proxy;
    }

    assert(err_or_warn);
    *out_result = (ag_dnsproxy_init_result) err_or_warn->value();
    *out_message = strdup(err_or_warn->str().c_str());

    delete proxy;
    return nullptr;
}

void ag_dnsproxy_deinit(ag_dnsproxy *handle) {
    auto proxy = (DnsProxy *) handle;
    proxy->deinit();
    delete proxy;
}

static std::optional<DnsMessageInfo> marshal_dns_message_info(const ag_dns_message_info *c_info) {
    if (!c_info) {
        return std::nullopt;
    }
    DnsMessageInfo info;
    info.transparent = c_info->transparent;
    return info;
}

ag_buffer ag_dnsproxy_handle_message(ag_dnsproxy *handle, ag_buffer message, const ag_dns_message_info *c_info) {
    auto *proxy = (DnsProxy *) handle;
    auto info = marshal_dns_message_info(c_info);
    Uint8Vector res = proxy->handle_message_sync({message.data, message.size}, opt_as_ptr(info));
    ag_buffer res_buf = marshal_buffer({res.data(), res.size()});
    return res_buf;
}

void ag_dnsproxy_handle_message_async(ag_dnsproxy *handle, ag_buffer c_message, const ag_dns_message_info *c_info,
        ag_handle_message_async_cb handler) {
    auto *proxy = (DnsProxy *) handle;
    auto info = marshal_dns_message_info(c_info);
    Uint8Vector message;
    message.assign(c_message.data, c_message.data + c_message.size);
    coro::run_detached([](DnsProxy *proxy, Uint8Vector message, std::optional<DnsMessageInfo> info,
                               ag_handle_message_async_cb handler) -> coro::Task<void> {
        auto result = co_await proxy->handle_message({message.data(), message.size()}, opt_as_ptr(info));
        ag_buffer result_buffer{.data = result.data(), .size = (uint32_t) result.size()};
        handler(&result_buffer);
    }(proxy, std::move(message), std::move(info), handler));
}

ag_dnsproxy_settings *ag_dnsproxy_get_settings(ag_dnsproxy *handle) {
    auto *proxy = (DnsProxy *) handle;
    ag_dnsproxy_settings *settings = marshal_settings(proxy->get_settings());
    return settings;
}

void ag_set_log_level(ag_log_level level) {
    Logger::set_log_level((LogLevel) level);
}

ag_dns_stamp *ag_dns_stamp_from_str(const char *stamp_str, const char **error) {
    auto stamp = ServerStamp::from_string(stamp_str);
    if (stamp.has_error()) {
        *error = marshal_str(stamp.error()->str());
        return nullptr;
    }
    auto *c_result = (ag_dns_stamp *) std::calloc(1, sizeof(ag_dns_stamp));
    c_result->proto = (ag_stamp_proto_type) stamp->proto;
    c_result->path = marshal_str(stamp->path);
    c_result->server_addr = marshal_str(stamp->server_addr_str);
    c_result->provider_name = marshal_str(stamp->provider_name);
    if (const auto &key = stamp->server_pk; !key.empty()) {
        c_result->server_public_key = marshal_buffer({key.data(), key.size()});
    }
    if (const auto &hashes = stamp->hashes; !hashes.empty()) {
        c_result->hashes = {(ag_buffer *) std::malloc(hashes.size() * sizeof(ag_buffer)), (uint32_t) hashes.size()};
        for (size_t i = 0; i < hashes.size(); ++i) {
            const auto &h = hashes[i];
            c_result->hashes.data[i] = marshal_buffer({h.data(), h.size()});
        }
    }
    if (stamp->props.has_value()) {
        c_result->properties = (ag_server_informal_properties*) std::malloc(sizeof(ag_server_informal_properties));
        *c_result->properties = (ag_server_informal_properties) stamp->props.value();
    }
    return c_result;
}

void ag_dns_stamp_free(ag_dns_stamp *stamp) {
    if (!stamp) {
        return;
    }
    std::free((void *) stamp->path);
    std::free((void *) stamp->server_addr);
    std::free((void *) stamp->provider_name);
    ag_buffer_free(stamp->server_public_key);
    for (uint32_t i = 0; i < stamp->hashes.size; ++i) {
        ag_buffer_free(stamp->hashes.data[i]);
    }
    std::free((void *) stamp->hashes.data);
    if (stamp->properties) {
        std::free((void *) stamp->properties);
    }
    std::free(stamp);
}

const char *ag_test_upstream(const ag_upstream_options *c_upstream, uint32_t timeout_ms, bool ipv6_available,
        ag_certificate_verification_cb on_certificate_verification, bool offline) {
    auto upstream = marshal_upstream(*c_upstream);
    ag_dnsproxy_events c_events{};
    c_events.on_certificate_verification = on_certificate_verification;
    auto events = marshal_events(&c_events);
    auto result =
            test_upstream(upstream, Millis{timeout_ms}, ipv6_available, events.on_certificate_verification, offline);
    return result ? marshal_str(result->str()) : marshal_str("");
}

bool ag_is_valid_dns_rule(const char *str) {
    return DnsFilter::is_valid_rule(str);
}

void ag_str_free(const char *str) {
    std::free((void *) str);
}

#include "ag_dns_h_hash.inc"

const char *ag_get_capi_version() {
    return AG_DNSLIBS_H_HASH;
}

void ag_set_log_callback(ag_log_cb callback, void *attachment) {
    if (callback) {
        Logger::set_callback([callback, attachment](LogLevel level, std::string_view message) {
            callback(attachment, (ag_log_level) level, message.data(), message.size());
        });
    } else {
        Logger::set_callback(nullptr);
    }
}

const char *ag_dnsproxy_version() {
    return DnsProxy::version();
}

const char *ag_dns_stamp_to_str(ag_dns_stamp *c_stamp) {
    if (c_stamp->properties) {
        ServerStamp stamp = marshal_stamp(c_stamp);
        return marshal_str(stamp.str());
    }

    return ag_dns_stamp_pretty_url(c_stamp);
    
}

const char *ag_dns_stamp_pretty_url(ag_dns_stamp *c_stamp) {
    ServerStamp stamp = marshal_stamp(c_stamp);
    return marshal_str(stamp.pretty_url(false));
}

const char *ag_dns_stamp_prettier_url(ag_dns_stamp *c_stamp) {
    ServerStamp stamp = marshal_stamp(c_stamp);
    return marshal_str(stamp.pretty_url(true));
}

ag_dns_filtering_log_action *ag_dns_filtering_log_action_from_event(const ag_dns_request_processed_event *c_event) {
    auto event = marshal_processed_event(c_event);
    auto action = DnsFilter::suggest_action(event);
    if (!action) {
        return nullptr;
    }
    auto **templates = new const char *[action->templates.size()];
    for (size_t i = 0; i < action->templates.size(); ++i) {
        templates[i] = strdup(action->templates[i].text.c_str());
    }
    return new ag_dns_filtering_log_action{
            .templates = {
                    .data = (const ag_dns_rule_template **) templates,
                    .size = (uint32_t) action->templates.size(),
            },
            .allowed_options = action->allowed_options,
            .required_options = action->required_options,
            .blocking = action->blocking,
    };
}

void ag_dns_filtering_log_action_free(ag_dns_filtering_log_action *action) {
    if (!action) {
        return;
    }
    for (uint32_t i = 0; i < action->templates.size; ++i) {
        free((void *) action->templates.data[i]);
    }
    delete[] action->templates.data;
    delete action;
}

char *ag_dns_generate_rule_with_options(
        const ag_dns_rule_template *tmplt, const ag_dns_request_processed_event *c_event, uint32_t options) {
    auto event = marshal_processed_event(c_event);
    DnsFilter::RuleTemplate rule_template((const char *) tmplt);
    return strdup(DnsFilter::generate_rule(rule_template, event, options).c_str());
}
