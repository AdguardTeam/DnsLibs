#include <dnsproxy.h>
#include <upstream.h>
#include <dnsfilter.h>
#include <ag_logger.h>
#include <ag_utils.h>

#include <ldns/packet.h>
#include <ldns/keys.h>
#include <ldns/rbtree.h>
#include <ldns/host2str.h>
#include <ldns/wire2host.h>
#include <ldns/host2wire.h>
#include <ldns/dname.h>
#include <ldns/rr.h>
#include <ldns/rdata.h>


#define errlog_id(l_, pkt_, fmt_, ...) errlog((l_), "[{}] " fmt_, ldns_pkt_id(pkt_), ##__VA_ARGS__)
#define errlog_fid(l_, pkt_, fmt_, ...) errlog((l_), "[{}] {} " fmt_, ldns_pkt_id(pkt_), __func__, ##__VA_ARGS__)
#define warnlog_id(l_, pkt_, fmt_, ...) warnlog((l_), "[{}] " fmt_, ldns_pkt_id(pkt_), ##__VA_ARGS__)
#define warnlog_fid(l_, pkt_, fmt_, ...) warnlog((l_), "[{}] {} " fmt_, ldns_pkt_id(pkt_), __func__, ##__VA_ARGS__)
#define dbglog_id(l_, pkt_, fmt_, ...) dbglog((l_), "[{}] " fmt_, ldns_pkt_id(pkt_), ##__VA_ARGS__)
#define dbglog_fid(l_, pkt_, fmt_, ...) dbglog((l_), "[{}] {} " fmt_, ldns_pkt_id(pkt_), __func__, ##__VA_ARGS__)
#define tracelog_id(l_, pkt_, fmt_, ...) tracelog((l_), "[{}] " fmt_, ldns_pkt_id(pkt_), ##__VA_ARGS__)
#define tracelog_fid(l_, pkt_, fmt_, ...) tracelog((l_), "[{}] {} " fmt_, ldns_pkt_id(pkt_), __func__, ##__VA_ARGS__)


using namespace ag;
using namespace std::chrono;
using ldns_pkt_ptr = std::unique_ptr<ldns_pkt, decltype(&ldns_pkt_free)>;


static constexpr milliseconds DEFAULT_UPSTREAM_TIMEOUT = milliseconds(30);
static constexpr std::string_view MOZILLA_DOH_HOST = "use-application-dns.net.";

static const dnsproxy_settings DEFAULT_PROXY_SETTINGS = {
    .upstreams = {
        { "8.8.8.8:53", { {}, DEFAULT_UPSTREAM_TIMEOUT, {} } },
        { "8.8.4.4:53", { {}, DEFAULT_UPSTREAM_TIMEOUT, {} } },
    },
    .blocked_response_ttl = 3600,
    .filter_params = {},
};

const dnsproxy_settings &dnsproxy_settings::get_default() {
    return DEFAULT_PROXY_SETTINGS;
}


struct dnsproxy::impl {
    ag::logger log;
    std::vector<upstream_ptr> upstreams;
    dnsfilter filter;
    dnsfilter::handle filter_handle = nullptr;
    dnsproxy_settings settings;
    dnsproxy_events events;

    ldns_rr *create_soa(const ldns_pkt *request) const;
    ldns_pkt *create_nxdomain_response(const ldns_pkt *request) const;
    ldns_pkt *create_arecord_response(const ldns_pkt *request, const ag::dnsfilter::rule **rules) const;
    ldns_pkt *create_aaaarecord_response(const ldns_pkt *request, const ag::dnsfilter::rule **rules) const;
    ldns_pkt *create_response_with_ips(const ldns_pkt *request,
        const std::vector<const ag::dnsfilter::rule *> &rules) const;
    ldns_pkt *create_blocking_response(const ldns_pkt *request,
        const std::vector<const ag::dnsfilter::rule *> &rules) const;

    void complete_processed_event(dns_request_processed_event event,
        const ldns_pkt *request, const ldns_pkt *response,
        const std::vector<const dnsfilter::rule *> &rules, std::string error) const;
};

static void log_packet(const ag::logger &log, const ldns_pkt *packet, const char *pkt_name) {
    if (!log->should_log((spdlog::level::level_enum)ag::DEBUG)) {
        return;
    }

    ldns_buffer *str_dns = ldns_buffer_new(512);
    ldns_status status = ldns_pkt2buffer_str(str_dns, packet);
    if (status != LDNS_STATUS_OK) {
        dbglog_id(log, packet, "failed to print {}: {} ({})"
            , pkt_name, ldns_get_errorstr_by_id(status), status);
    } else {
        dbglog_id(log, packet, "{}:\n{}", pkt_name, (char*)ldns_buffer_begin(str_dns));
    }
    ldns_buffer_free(str_dns);
}

static ldns_pkt *create_response_by_request(const ldns_pkt *request) {
    const ldns_rr *question = ldns_rr_list_rr(ldns_pkt_question(request), 0);
    ldns_rr_type type = ldns_rr_get_type(question);
    if (type != LDNS_RR_TYPE_AAAA) {
        type = LDNS_RR_TYPE_A;
    }
    ldns_pkt *response = ldns_pkt_query_new(ldns_rdf_clone(ldns_rr_owner(question)),
        type, LDNS_RR_CLASS_IN, LDNS_RD | LDNS_RA);
    assert(response != nullptr);
    ldns_pkt_set_id(response, ldns_pkt_id(request));
    ldns_pkt_set_qr(response, true); // answer flag
    ldns_pkt_set_qdcount(response, ldns_pkt_section_count(request, LDNS_SECTION_QUESTION));
    ldns_rr_list_deep_free(ldns_pkt_question(response));
    ldns_pkt_set_question(response, ldns_pkt_get_section_clone(request, LDNS_SECTION_QUESTION));

    return response;
}

static std::string get_mbox(const ldns_pkt *request) {
    const ldns_rr *question = ldns_rr_list_rr(ldns_pkt_question(request), 0);

    char *zone = ldns_rdf2str(ldns_rr_owner(question));
    std::string mbox = ag::utils::fmt_string("hostmaster.%s",
        (zone != nullptr && strlen(zone) > 0 && zone[0] != '.') ? zone : "");
    free(zone);

    return mbox;
}

// Taken from AdGuardHome/dnsforward.go/genSOA
ldns_rr *dnsproxy::impl::create_soa(const ldns_pkt *request) const {
    const ldns_rr *question = ldns_rr_list_rr(ldns_pkt_question(request), 0);
    std::string mbox = get_mbox(request);

    ldns_rr *soa = ldns_rr_new();
    assert(soa != nullptr);
    ldns_rr_set_owner(soa, ldns_rdf_clone(ldns_rr_owner(question)));
    ldns_rr_set_ttl(soa, this->settings.blocked_response_ttl);
    ldns_rr_set_type(soa, LDNS_RR_TYPE_SOA);
    ldns_rr_set_class(soa, LDNS_RR_CLASS_IN);
    // fill soa rdata
    ldns_rr_push_rdf(soa, ldns_dname_new_frm_str("fake-for-negative-caching.adguard.com.")); // MNAME
    ldns_rr_push_rdf(soa, ldns_dname_new_frm_str(mbox.c_str())); // RNAME
    ldns_rr_push_rdf(soa, ldns_native2rdf_int32(LDNS_RDF_TYPE_TIME, time(nullptr) + 100500)); // SERIAL
    ldns_rr_push_rdf(soa, ldns_native2rdf_int32(LDNS_RDF_TYPE_PERIOD, 1800)); // REFRESH
    ldns_rr_push_rdf(soa, ldns_native2rdf_int32(LDNS_RDF_TYPE_PERIOD, 900)); // RETRY
    ldns_rr_push_rdf(soa, ldns_native2rdf_int32(LDNS_RDF_TYPE_PERIOD, 604800)); // EXPIRE
    ldns_rr_push_rdf(soa, ldns_native2rdf_int32(LDNS_RDF_TYPE_PERIOD, 86400)); // MINIMUM

    return soa;
}

ldns_pkt *dnsproxy::impl::create_nxdomain_response(const ldns_pkt *request) const {
    tracelog_fid(log, request, "");

    ldns_pkt *response = create_response_by_request(request);
    ldns_pkt_set_rcode(response, LDNS_RCODE_NXDOMAIN);
    ldns_pkt_push_rr(response, LDNS_SECTION_AUTHORITY, create_soa(request));

    return response;
}

ldns_pkt *dnsproxy::impl::create_arecord_response(const ldns_pkt *request,
        const ag::dnsfilter::rule **rules) const {
    tracelog_fid(log, request, "");
    const ldns_rr *question = ldns_rr_list_rr(ldns_pkt_question(request), 0);

    ldns_rr *answer = ldns_rr_new();
    assert(answer != nullptr);
    ldns_rr_set_owner(answer, ldns_rdf_clone(ldns_rr_owner(question)));
    ldns_rr_set_ttl(answer, this->settings.blocked_response_ttl);
    ldns_rr_set_type(answer, LDNS_RR_TYPE_A);
    ldns_rr_set_class(answer, LDNS_RR_CLASS_IN);
    for (size_t i = 0; rules[i] != nullptr; ++i) {
        const std::string &ip = rules[i]->ip.value();
        ldns_rr_push_rdf(answer, ldns_rdf_new_frm_str(LDNS_RDF_TYPE_A, ip.c_str()));
    }

    ldns_pkt *response = create_response_by_request(request);
    ldns_pkt_push_rr(response, LDNS_SECTION_ANSWER, answer);

    return response;
}

ldns_pkt *dnsproxy::impl::create_aaaarecord_response(const ldns_pkt *request,
        const ag::dnsfilter::rule **rules) const {
    tracelog_fid(log, request, "");
    const ldns_rr *question = ldns_rr_list_rr(ldns_pkt_question(request), 0);

    ldns_rr *answer = ldns_rr_new();
    assert(answer != nullptr);
    ldns_rr_set_owner(answer, ldns_rdf_clone(ldns_rr_owner(question)));
    ldns_rr_set_ttl(answer, this->settings.blocked_response_ttl);
    ldns_rr_set_type(answer, LDNS_RR_TYPE_AAAA);
    ldns_rr_set_class(answer, LDNS_RR_CLASS_IN);
    for (size_t i = 0; rules[i] != nullptr; ++i) {
        const std::string &ip = rules[i]->ip.value();
        ldns_rr_push_rdf(answer, ldns_rdf_new_frm_str(LDNS_RDF_TYPE_AAAA, ip.c_str()));
    }

    ldns_pkt *response = create_response_by_request(request);
    ldns_pkt_push_rr(response, LDNS_SECTION_ANSWER, answer);
    return response;
}

ldns_pkt *dnsproxy::impl::create_response_with_ips(const ldns_pkt *request,
        const std::vector<const ag::dnsfilter::rule *> &rules) const {
    const ldns_rr *question = ldns_rr_list_rr(ldns_pkt_question(request), 0);
    ldns_rr_type type = ldns_rr_get_type(question);
    if (type == LDNS_RR_TYPE_A) {
        const ag::dnsfilter::rule *ipv4_rules[rules.size() + 1];
        std::fill(ipv4_rules, ipv4_rules + rules.size(), nullptr);
        size_t num = 0;
        for (const ag::dnsfilter::rule *r : rules) {
            if (ag::utils::is_valid_ip4(r->ip.value())) {
                ipv4_rules[num++] = r;
            }
        }
        if (num > 0) {
            return create_arecord_response(request, ipv4_rules);
        }
    } else if (type == LDNS_RR_TYPE_AAAA) {
        const ag::dnsfilter::rule *ipv6_rules[rules.size() + 1];
        std::fill(ipv6_rules, ipv6_rules + rules.size(), nullptr);
        size_t num = 0;
        for (const ag::dnsfilter::rule *r : rules) {
            if (!ag::utils::is_valid_ip4(r->ip.value())) {
                ipv6_rules[num++] = r;
            }
        }
        if (num > 0) {
            return create_aaaarecord_response(request, ipv6_rules);
        }
    }
    // empty response
    ldns_pkt *response = create_response_by_request(request);
    ldns_pkt_push_rr(response, LDNS_SECTION_AUTHORITY, create_soa(request));
    return response;
}

ldns_pkt *dnsproxy::impl::create_blocking_response(const ldns_pkt *request,
        const std::vector<const ag::dnsfilter::rule *> &rules) const {
    const ldns_rr *question = ldns_rr_list_rr(ldns_pkt_question(request), 0);
    ldns_rr_type type = ldns_rr_get_type(question);
    ldns_pkt *response;
    if ((type != LDNS_RR_TYPE_A && type != LDNS_RR_TYPE_AAAA)
            || !rules[0]->ip.has_value()) {
        response = create_nxdomain_response(request);
    } else {
        response = create_response_with_ips(request, rules);
    }

    log_packet(this->log, response, "blocking dns response");

    return response;
}

void dnsproxy::impl::complete_processed_event(dns_request_processed_event event,
        const ldns_pkt *request, const ldns_pkt *response,
        const std::vector<const dnsfilter::rule *> &rules, std::string error) const {
    if (this->events.on_request_processed == nullptr) {
        return;
    }

    if (request != nullptr) {
        const ldns_rr *question = ldns_rr_list_rr(ldns_pkt_question(request), 0);
        char *type = ldns_rr_type2str(ldns_rr_get_type(question));
        event.type = type;
        free(type);
    }

    event.elapsed = duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count() - event.start_time;

    if (response != nullptr) {
        char *answer = ldns_rr_list2str(ldns_pkt_answer(response));
        event.answer = answer;
        free(answer);
    }

    event.rules.reserve(rules.size());
    event.filter_list_ids.reserve(rules.size());
    for (const dnsfilter::rule *rule : rules) {
        event.rules.push_back(rule->text);
        event.filter_list_ids.push_back(rule->filter_id);
    }

    event.whitelist = rules.size() > 0 && rules[0]->props.test(dnsfilter::RP_EXCEPTION);

    event.error = std::move(error);

    this->events.on_request_processed(std::move(event));
}

static std::vector<uint8_t> transform_response_to_raw_data(const ldns_pkt *message) {
    ldns_buffer *buffer = ldns_buffer_new(512);
    ldns_status status = ldns_pkt2buffer_wire(buffer, message);
    assert(status == LDNS_STATUS_OK);
    // @todo: custom allocator will allow to avoid data copy
    std::vector<uint8_t> data =
        { ldns_buffer_at(buffer, 0), ldns_buffer_at(buffer, 0) + ldns_buffer_position(buffer) };
    ldns_buffer_free(buffer);
    return data;
}

dnsproxy::dnsproxy()
    : pimpl(new dnsproxy::impl)
{}

dnsproxy::~dnsproxy() = default;

bool dnsproxy::init(dnsproxy_settings settings, dnsproxy_events events) {
    std::unique_ptr<impl> &proxy = this->pimpl;
    pimpl->log = ag::create_logger("dnsproxy");

    infolog(proxy->log, "Initializing proxy module...");

    infolog(proxy->log, "Initializing upstreams...");
    proxy->upstreams.reserve(settings.upstreams.size());
    for (dnsproxy_settings::upstream_settings &us : settings.upstreams) {
        infolog(proxy->log, "Initializing upstream {}...", us.dns_server);
        auto[upstream, err] = ag::upstream::address_to_upstream(us.dns_server, us.options);
        if (err.has_value()) {
            errlog(proxy->log, "Failed to create upstream: {}", err.value().c_str());
        } else {
            proxy->upstreams.emplace_back(std::move(upstream));
            infolog(proxy->log, "Upstream created successfully");
        }
    }
    if (proxy->upstreams.size() == 0) {
        errlog(proxy->log, "Failed to initialized any upstream");
        this->deinit();
        return false;
    }
    infolog(proxy->log, "Upstreams initialized");

    infolog(proxy->log, "Initializing filtering module...");
    std::optional<ag::dnsfilter::handle> handle = proxy->filter.create(settings.filter_params);
    if (!handle.has_value()) {
        errlog(proxy->log, "failed to initialize filtering module");
        this->deinit();
        return false;
    }
    proxy->filter_handle = handle.value();
    infolog(proxy->log, "Filtering module initialized");

    proxy->settings = std::move(settings);
    proxy->events = std::move(events);

    infolog(proxy->log, "Proxy module initialized");
    return true;
}

void dnsproxy::deinit() {
    std::unique_ptr<impl> &proxy = this->pimpl;
    proxy->upstreams.clear();
    proxy->filter.destroy(proxy->filter_handle);
    proxy->settings = {};
}

const dnsproxy_settings &dnsproxy::get_settings() const {
    return this->pimpl->settings;
}

std::vector<uint8_t> dnsproxy::handle_message(ag::uint8_view_t message) {
    dns_request_processed_event event = {};
    event.start_time = duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();

    std::unique_ptr<impl> &proxy = this->pimpl;

    ldns_pkt *request;
    ldns_status status = ldns_wire2pkt(&request, message.data(), message.length());
    if (status != LDNS_STATUS_OK) {
        std::string err = ag::utils::fmt_string("failed to parse payload: {} ({})",
            ldns_get_errorstr_by_id(status), status);
        errlog(proxy->log, "{} {}", __func__, err.c_str());
        proxy->complete_processed_event(std::move(event), nullptr, nullptr, {}, std::move(err));
        return {};
    }
    ldns_pkt_ptr req_holder = ldns_pkt_ptr(request, ldns_pkt_free);
    log_packet(proxy->log, request, "client dns request");

    const ldns_rr *question = ldns_rr_list_rr(ldns_pkt_question(request), 0);
    auto domain = std::unique_ptr<char, decltype(&free)>(ldns_rdf2str(ldns_rr_owner(question)), free);
    event.domain = domain.get();

    // disable Mozilla DoH
    ldns_rr_type type = ldns_rr_get_type(question);
    if ((type == LDNS_RR_TYPE_A || type == LDNS_RR_TYPE_AAAA)
            && 0 == strcmp(domain.get(), MOZILLA_DOH_HOST.data())) {
        ldns_pkt_ptr response = { proxy->create_nxdomain_response(request), &ldns_pkt_free };
        log_packet(proxy->log, response.get(), "mozilla doh blocking response");
        std::vector<uint8_t> raw_response = transform_response_to_raw_data(response.get());
        proxy->complete_processed_event(std::move(event), request, response.get(), {}, "");
        return raw_response;
    }

    std::string_view pure_domain = domain.get();
    if (ldns_dname_str_absolute(domain.get())) {
        pure_domain.remove_suffix(1); // drop trailing dot
    }
    tracelog_fid(proxy->log, request, "query domain: {}", pure_domain);

    std::vector<ag::dnsfilter::rule> rules = proxy->filter.match(proxy->filter_handle, pure_domain);
    for (const ag::dnsfilter::rule &rule : rules) {
        tracelog_fid(proxy->log, request, "matched rule: {}", rule.text.c_str());
    }

    std::vector<const ag::dnsfilter::rule *> effective_rules =
        ag::dnsfilter::get_effective_rules(rules);
    if (effective_rules.size() > 0
            && !effective_rules[0]->props.test(ag::dnsfilter::RP_EXCEPTION)) {
        dbglog_fid(proxy->log, request, "dns query blocked by rule: {}", effective_rules[0]->text.c_str());
        ldns_pkt_ptr response = { proxy->create_blocking_response(request, effective_rules), &ldns_pkt_free };
        log_packet(proxy->log, response.get(), "rule blocked response");
        std::vector<uint8_t> raw_response = transform_response_to_raw_data(response.get());
        proxy->complete_processed_event(std::move(event), request, response.get(), effective_rules, "");
        return raw_response;
    }

    auto[response, err] = proxy->upstreams[0]->exchange(request);
    event.upstream_addr = proxy->upstreams[0]->address();
    if (err.has_value()) {
        std::string err_str = ag::utils::fmt_string("Upstream failed to perform dns query: {}",
            err.value().c_str());
        errlog_fid(proxy->log, request, "{}" , err_str.c_str());
        proxy->complete_processed_event(std::move(event), request, nullptr, effective_rules, std::move(err_str));
        return {};
    }

    ldns_pkt_ptr resp_holder = { response, &ldns_pkt_free };
    log_packet(proxy->log, response, "upstream dns response");
    std::vector<uint8_t> raw_response = transform_response_to_raw_data(response);
    event.bytes_received = raw_response.size();
    event.bytes_sent = message.size();
    proxy->complete_processed_event(std::move(event), request, response, effective_rules, "");
    return raw_response;
}

