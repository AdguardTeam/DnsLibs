#include <ag_dns.h>

#include <cstring>

#include <spdlog/sinks/base_sink.h>

#include <dnsproxy.h>
#include <upstream_utils.h>

#ifdef _WIN32
#include <detours.h>

/**
 * Deactivated version of SetUnhandledExceptionFilter that does nothing.
 * This is needed because there are many places in runtime where SetUnhandledExceptionFilter is called.
 * @param lpTopLevelExceptionFilter Pointer to exception filter function
 * @return Pointer if success, NULL if error is occurred. This function always succeeds.
 */
static LPTOP_LEVEL_EXCEPTION_FILTER WINAPI
DontSetUnhandledExceptionFilter(LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter) {
    // Do nothing
    return lpTopLevelExceptionFilter;
}

static void *detoursHook_SetUnhandledExceptionFilter = (void *)SetUnhandledExceptionFilter;

void ag_disable_SetUnhandledExceptionFilter(void) {
    DetourTransactionBegin();
    DetourAttach(&detoursHook_SetUnhandledExceptionFilter, (void *)DontSetUnhandledExceptionFilter);
    DetourTransactionCommit();
}

void ag_enable_SetUnhandledExceptionFilter(void) {
    DetourTransactionBegin();
    DetourDetach(&detoursHook_SetUnhandledExceptionFilter, (void *)DontSetUnhandledExceptionFilter);
    DetourTransactionCommit();
}
#endif // _WIN32

static constexpr const char *AGCVR_TO_STRING[] = {
        [AGCVR_ERROR_CREATE_CERT] = "ERROR_CREATE_CERT",
        [AGCVR_ERROR_ACCESS_TO_STORE] = "ERROR_ACCESS_TO_STORE",
        [AGCVR_ERROR_CERT_VERIFICATION] = "ERROR_CERT_VERIFICATION",
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

static void free_listeners(ag_listener_settings *listeners, size_t n) {
    for (size_t i = 0; i < n; ++i) {
        ag_listener_settings &o = listeners[i];
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

static ag_buffer marshal_buffer(ag::uint8_view v) {
    ag_buffer buf;
    buf.size = v.size();
    buf.data = (uint8_t *) std::malloc(buf.size);
    std::memcpy((void *) buf.data, v.data(), buf.size);
    return buf;
}

void ag_buffer_free(ag_buffer buf) {
    std::free((void *) buf.data);
}

static char **marshal_strs(const std::vector<std::string> &strs) {
    if (strs.empty()) {
        return nullptr;
    }
    char **c_strs = (char **) std::malloc(strs.size() * sizeof(char *));
    for (size_t i = 0; i < strs.size(); ++i) {
        c_strs[i] = marshal_str(strs[i]);
    }
    return c_strs;
}

static ag_upstream_options marshal_upstream(const ag::upstream_options &upstream) {
    ag_upstream_options c_upstream{};

    c_upstream.address = marshal_str(upstream.address);
    c_upstream.id = upstream.id;
    c_upstream.timeout_ms = upstream.timeout.count();

    if (const ag::ipv4_address_array *arr4 = std::get_if<ag::ipv4_address_array>(&upstream.resolved_server_ip)) {
        c_upstream.resolved_ip_address = marshal_buffer({arr4->data(), arr4->size()});
    } else if (const ag::ipv6_address_array *arr6 = std::get_if<ag::ipv6_address_array>(&upstream.resolved_server_ip)) {
        c_upstream.resolved_ip_address = marshal_buffer({arr6->data(), arr6->size()});
    }

    c_upstream.bootstrap.size = upstream.bootstrap.size();
    c_upstream.bootstrap.data = (const char **) marshal_strs(upstream.bootstrap);

    if (const uint32_t *idx = std::get_if<uint32_t>(&upstream.outbound_interface)) {
        c_upstream.outbound_interface_index = *idx;
    }

    return c_upstream;
}

static ag_upstream_options *marshal_upstreams(const std::vector<ag::upstream_options> &upstreams) {
    if (upstreams.empty()) {
        return nullptr;
    }
    auto *c_upstreams = (ag_upstream_options *) std::malloc(upstreams.size() * sizeof(ag_upstream_options));
    for (size_t i = 0; i < upstreams.size(); ++i) {
        c_upstreams[i] = marshal_upstream(upstreams[i]);
    }
    return c_upstreams;
}

static ag_dns64_settings *marshal_dns64(const std::optional<ag::dns64_settings> &dns64) {
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

static ag_filter_params marshal_filter_params(const ag::dnsfilter::filter_params &params) {
    ag_filter_params c_params{};
    c_params.data = marshal_str(params.data);
    c_params.in_memory = params.in_memory;
    c_params.id = params.id;
    return c_params;
}

static ag_filter_params *marshal_filters(const std::vector<ag::dnsfilter::filter_params> &filters) {
    if (filters.empty()) {
        return nullptr;
    }
    auto *c_filters = (ag_filter_params *) std::malloc(filters.size() * sizeof(ag_filter_params));
    for (size_t i = 0; i < filters.size(); ++i) {
        c_filters[i] = marshal_filter_params(filters[i]);
    }
    return c_filters;
}

static ag_filter_engine_params marshal_engine_params(const ag::dnsfilter::engine_params &params) {
    ag_filter_engine_params c_params{};
    c_params.filters.size = params.filters.size();
    c_params.filters.data = marshal_filters(params.filters);
    return c_params;
}

static ag_listener_settings marshal_listener(const ag::listener_settings &listener) {
    ag_listener_settings c_listener{};
    c_listener.address = marshal_str(listener.address);
    c_listener.port = listener.port;
    c_listener.protocol = (ag_listener_protocol) listener.protocol;
    c_listener.persistent = listener.persistent;
    c_listener.idle_timeout_ms = listener.idle_timeout.count();
    return c_listener;
}

static ag_listener_settings *marshal_listeners(const std::vector<ag::listener_settings> &listeners) {
    if (listeners.empty()) {
        return nullptr;
    }
    auto *c_listeners = (ag_listener_settings *) std::malloc(listeners.size() * sizeof(ag_listener_settings));
    for (size_t i = 0; i < listeners.size(); ++i) {
        c_listeners[i] = marshal_listener(listeners[i]);
    }
    return c_listeners;
}

static ag_dnsproxy_settings *marshal_settings(const ag::dnsproxy_settings &settings) {
    auto *c_settings = (ag_dnsproxy_settings *) std::malloc(sizeof(ag_dnsproxy_settings));

    c_settings->block_ipv6 = settings.block_ipv6;
    c_settings->ipv6_available = settings.ipv6_available;
    c_settings->dns_cache_size = settings.dns_cache_size;
    c_settings->blocked_response_ttl_secs = settings.blocked_response_ttl_secs;
    c_settings->blocking_mode = (ag_dnsproxy_blocking_mode) settings.blocking_mode;
    c_settings->custom_blocking_ipv4 = marshal_str(settings.custom_blocking_ipv4);
    c_settings->custom_blocking_ipv6 = marshal_str(settings.custom_blocking_ipv6);
    c_settings->dns64 = marshal_dns64(settings.dns64);
    c_settings->upstreams.size = settings.upstreams.size();
    c_settings->upstreams.data = marshal_upstreams(settings.upstreams);
    c_settings->fallbacks.size = settings.fallbacks.size();
    c_settings->fallbacks.data = marshal_upstreams(settings.fallbacks);
    c_settings->handle_dns_suffixes = settings.handle_dns_suffixes;
    c_settings->dns_suffixes.size = settings.dns_suffixes.size();
    c_settings->dns_suffixes.data = (const char **) marshal_strs(settings.dns_suffixes);
    c_settings->filter_params = marshal_engine_params(settings.filter_params);
    c_settings->listeners.size = settings.listeners.size();
    c_settings->listeners.data = marshal_listeners(settings.listeners);
    c_settings->optimistic_cache = settings.optimistic_cache;
    c_settings->enable_dnssec_ok = settings.enable_dnssec_ok;

    return c_settings;
}

void ag_dnsproxy_settings_free(ag_dnsproxy_settings *settings) {
    if (!settings) {
        return;
    }
    std::free((void *) settings->custom_blocking_ipv6);
    std::free((void *) settings->custom_blocking_ipv4);
    free_upstreams(settings->upstreams.data, settings->upstreams.size);
    free_upstreams(settings->fallbacks.data, settings->fallbacks.size);
    for (size_t i = 0; i < settings->dns_suffixes.size; ++i) {
        ag_str_free(settings->dns_suffixes.data[i]);
    }
    std::free(settings->dns_suffixes.data);
    free_dns64(settings->dns64);
    free_listeners(settings->listeners.data, settings->listeners.size);
    free_filters(settings->filter_params.filters.data, settings->filter_params.filters.size);
    std::free(settings);
}

static ag::upstream_options marshal_upstream(const ag_upstream_options &c_upstream) {
    ag::upstream_options upstream{};
    if (c_upstream.address) {
        upstream.address.assign(c_upstream.address);
    }
    upstream.id = c_upstream.id;
    upstream.timeout = std::chrono::milliseconds{c_upstream.timeout_ms};
    if (c_upstream.resolved_ip_address.size == ag::ipv4_address_size) {
        ag::ipv4_address_array arr4;
        std::memcpy(arr4.data(), c_upstream.resolved_ip_address.data, arr4.size());
        upstream.resolved_server_ip = arr4;
    } else if (c_upstream.resolved_ip_address.size == ag::ipv6_address_size) {
        ag::ipv6_address_array arr6;
        std::memcpy(arr6.data(), c_upstream.resolved_ip_address.data, arr6.size());
        upstream.resolved_server_ip = arr6;
    }
    for (size_t i = 0; i < c_upstream.bootstrap.size; ++i) {
        upstream.bootstrap.emplace_back(c_upstream.bootstrap.data[i]);
    }
    if (c_upstream.outbound_interface_index != 0) {
        upstream.outbound_interface = c_upstream.outbound_interface_index;
    }
    return upstream;
}

static std::vector<ag::upstream_options> marshal_upstreams(const ag_upstream_options *c_upstreams, size_t n) {
    std::vector<ag::upstream_options> upstreams;
    upstreams.reserve(n);
    for (size_t i = 0; i < n; ++i) {
        upstreams.emplace_back(marshal_upstream(c_upstreams[i]));
    }
    return upstreams;
}

static ag::listener_settings marshal_listener(const ag_listener_settings &c_listener) {
    ag::listener_settings listener{};
    if (c_listener.address) {
        listener.address.assign(c_listener.address);
    }
    listener.port = c_listener.port;
    listener.protocol = (ag::listener_protocol) c_listener.protocol;
    listener.persistent = c_listener.persistent;
    listener.idle_timeout = std::chrono::milliseconds{c_listener.idle_timeout_ms};
    return listener;
}

static std::vector<ag::listener_settings> marshal_listeners(const ag_listener_settings *c_listeners, size_t n) {
    std::vector<ag::listener_settings> listeners;
    listeners.reserve(n);
    for (size_t i = 0; i < n; ++i) {
        listeners.emplace_back(marshal_listener(c_listeners[i]));
    }
    return listeners;
}

static ag::dnsfilter::filter_params marshal_filter_params(const ag_filter_params &c_params) {
    ag::dnsfilter::filter_params params{};
    if (c_params.data) {
        params.data.assign(c_params.data);
    }
    params.in_memory = c_params.in_memory;
    params.id = c_params.id;
    return params;
}

static std::vector<ag::dnsfilter::filter_params> marshal_filters(const ag_filter_params *c_filters, size_t n) {
    std::vector<ag::dnsfilter::filter_params> filters;
    filters.reserve(n);
    for (size_t i = 0; i < n; ++i) {
        filters.emplace_back(marshal_filter_params(c_filters[i]));
    }
    return filters;
}

static ag::dnsproxy_settings marshal_settings(const ag_dnsproxy_settings *c_settings) {
    ag::dnsproxy_settings settings{};

    settings.block_ipv6 = c_settings->block_ipv6;
    settings.ipv6_available = c_settings->ipv6_available;
    settings.dns_cache_size = c_settings->dns_cache_size;
    settings.blocked_response_ttl_secs = c_settings->blocked_response_ttl_secs;
    settings.blocking_mode = (ag::dnsproxy_blocking_mode) c_settings->blocking_mode;
    if (c_settings->custom_blocking_ipv4) {
        settings.custom_blocking_ipv4.assign(c_settings->custom_blocking_ipv4);
    }
    if (c_settings->custom_blocking_ipv6) {
        settings.custom_blocking_ipv6.assign(c_settings->custom_blocking_ipv6);
    }
    if (c_settings->dns64) {
        ag::dns64_settings dns64{};
        dns64.upstreams = marshal_upstreams(c_settings->dns64->upstreams.data,
                                            c_settings->dns64->upstreams.size);
        dns64.max_tries = c_settings->dns64->max_tries;
        dns64.wait_time = std::chrono::milliseconds{c_settings->dns64->wait_time_ms};
        settings.dns64 = dns64;
    }
    settings.upstreams = marshal_upstreams(c_settings->upstreams.data, c_settings->upstreams.size);
    settings.fallbacks = marshal_upstreams(c_settings->fallbacks.data, c_settings->fallbacks.size);
    settings.handle_dns_suffixes = c_settings->handle_dns_suffixes;
    settings.dns_suffixes.reserve(c_settings->dns_suffixes.size);
    for (size_t i = 0; i < c_settings->dns_suffixes.size; ++i) {
        settings.dns_suffixes.emplace_back(c_settings->dns_suffixes.data[i]);
    }
    settings.listeners = marshal_listeners(c_settings->listeners.data, c_settings->listeners.size);
    settings.filter_params.filters = marshal_filters(c_settings->filter_params.filters.data,
                                                     c_settings->filter_params.filters.size);
    settings.optimistic_cache = c_settings->optimistic_cache;
    settings.enable_dnssec_ok = c_settings->enable_dnssec_ok;

    return settings;
}

static const char *c_str_if_not_empty(const std::string &str) {
    return str.empty() ? nullptr : str.c_str();
}

static ag::dnsproxy_events marshal_events(const ag_dnsproxy_events *c_events) {
    ag::dnsproxy_events events{};
    if (!c_events) {
        return events;
    }
    if (c_events->on_request_processed) {
        events.on_request_processed = [cb = c_events->on_request_processed]
                (const ag::dns_request_processed_event &event) {
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
            std::for_each(event.rules.begin(),
                          event.rules.end(),
                          [&c_rules](auto &rule) { c_rules.push_back(rule.c_str()); });
            e.rules.data = c_rules.data();
            e.rules.size = c_rules.size();

            cb(&e);
        };
    }
    if (c_events->on_certificate_verification) {
        events.on_certificate_verification = [cb = c_events->on_certificate_verification]
                (const ag::certificate_verification_event &event) -> std::optional<std::string> {
            ag_certificate_verification_event e{};

            e.certificate.size = event.certificate.size();
            e.certificate.data = (uint8_t *) event.certificate.data();

            std::vector<ag_buffer> c_buffers;
            c_buffers.reserve(event.chain.size());
            std::for_each(event.chain.begin(),
                          event.chain.end(),
                          [&c_buffers](auto &cert) {
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
    const auto &settings = ag::dnsproxy_settings::get_default();
    auto *c_settings = marshal_settings(settings);
    return c_settings;
}

ag_dnsproxy *ag_dnsproxy_init(const ag_dnsproxy_settings *c_settings, const ag_dnsproxy_events *c_events) {
    auto settings = marshal_settings(c_settings);
    auto events = marshal_events(c_events);

    auto *proxy = new ag::dnsproxy;

    auto [ret, _] = proxy->init(settings, events);
    if (ret) {
        return (void *) proxy;
    }

    delete proxy;
    return nullptr;
}

void ag_dnsproxy_deinit(ag_dnsproxy *handle) {
    auto proxy = (ag::dnsproxy *) handle;
    proxy->deinit();
    delete proxy;
}

ag_buffer ag_dnsproxy_handle_message(ag_dnsproxy *handle, ag_buffer message) {
    auto proxy = (ag::dnsproxy *) handle;
    ag::uint8_vector res = proxy->handle_message({message.data, message.size});
    ag_buffer res_buf = marshal_buffer({res.data(), res.size()});
    return res_buf;
}

ag_dnsproxy_settings *ag_dnsproxy_get_settings(ag_dnsproxy *handle) {
    auto proxy = (ag::dnsproxy *) handle;
    ag_dnsproxy_settings *settings = marshal_settings(proxy->get_settings());
    return settings;
}

void ag_set_default_log_level(ag_log_level level) {
    ag::set_default_log_level((ag::log_level) level);
}

ag_parse_dns_stamp_result *ag_parse_dns_stamp(const char *stamp_str) {
    auto [stamp, error] = ag::server_stamp::from_string(stamp_str);
    auto *c_result = (ag_parse_dns_stamp_result *) std::calloc(1, sizeof(ag_parse_dns_stamp_result));
    c_result->stamp.proto = (ag_stamp_proto_type) stamp.proto;
    c_result->stamp.path = marshal_str(stamp.path);
    c_result->stamp.server_addr = marshal_str(stamp.server_addr_str);
    c_result->stamp.provider_name = marshal_str(stamp.provider_name);
    if (const auto &key = stamp.server_pk; !key.empty()) {
        c_result->stamp.server_public_key = marshal_buffer({ key.data(), key.size() });
    }
    if (const auto &hashes = stamp.hashes; !hashes.empty()) {
        c_result->stamp.hashes = { (ag_buffer *)std::malloc(hashes.size() * sizeof(ag_buffer)), (uint32_t)hashes.size() };
        for (size_t i = 0; i < hashes.size(); ++i) {
            const auto &h = hashes[i];
            c_result->stamp.hashes.data[i] = marshal_buffer({ h.data(), h.size() });
        }
    }
    c_result->stamp.properties = (ag_server_informal_properties)stamp.props;
    c_result->stamp.pretty_url = marshal_str(stamp.pretty_url(false));
    c_result->stamp.prettier_url = marshal_str(stamp.pretty_url(true));
    c_result->error = marshal_str(error.value_or(""));
    return c_result;
}

void ag_parse_dns_stamp_result_free(ag_parse_dns_stamp_result *result) {
    if (!result) {
        return;
    }
    std::free((void *) result->stamp.path);
    std::free((void *) result->stamp.server_addr);
    std::free((void *) result->stamp.provider_name);
    ag_buffer_free(result->stamp.server_public_key);
    for (uint32_t i = 0; i < result->stamp.hashes.size; ++i) {
        ag_buffer_free(result->stamp.hashes.data[i]);
    }
    std::free((void *) result->stamp.hashes.data);
    std::free((void *) result->stamp.pretty_url);
    std::free((void *) result->stamp.prettier_url);
    std::free((void *) result->error);
    std::free(result);
}

const char *ag_test_upstream(const ag_upstream_options *c_upstream,
                             ag_certificate_verification_cb on_certificate_verification) {
    auto upstream = marshal_upstream(*c_upstream);
    ag_dnsproxy_events c_events{};
    c_events.on_certificate_verification = on_certificate_verification;
    auto events = marshal_events(&c_events);
    auto result = ag::test_upstream(upstream, events.on_certificate_verification);
    return marshal_str(result.value_or(""));
}

void ag_str_free(const char *str) {
    std::free((void *) str);
}

#include "ag_dns_h_hash.inc"

const char *ag_get_capi_version() {
    return AG_DNSLIBS_H_HASH;
}

class callback_sink_mt : public spdlog::sinks::base_sink<std::mutex> {
public:
    static ag::logger create(const std::string &logger_name, ag_log_cb cb, void *arg) {
        return spdlog::default_factory::create<callback_sink_mt>(logger_name, cb, arg);
    }

    callback_sink_mt(ag_log_cb cb, void *cb_arg) : cb{cb}, cb_arg{cb_arg} {}

private:
    ag_log_cb cb;
    void *cb_arg;

    void sink_it_(const spdlog::details::log_msg &msg) final {
        if (!cb) {
            return;
        }
        std::string name{msg.logger_name.data(), msg.logger_name.size()};
        std::string message{msg.payload.data(), msg.payload.size()};
        cb(cb_arg, name.c_str(), (ag_log_level) msg.level, message.c_str());
    }

    void flush_() final {}
};

void ag_logger_set_default_callback(ag_log_cb callback, void *attachment) {
    ag::set_logger_factory_callback([callback, attachment](const std::string &name) {
        return callback_sink_mt::create(name, callback, attachment);
    });
}

const char *ag_dnsproxy_version() {
    return ag::dnsproxy::version();
}
