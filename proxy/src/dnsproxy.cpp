#include <dnsproxy.h>
#include <upstream.h>
#include <dns64.h>
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

#include <mutex>
#include <thread>
#include <atomic>

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


static constexpr milliseconds DEFAULT_UPSTREAM_TIMEOUT = milliseconds(30000);
static constexpr std::string_view MOZILLA_DOH_HOST = "use-application-dns.net.";

static const dnsproxy_settings DEFAULT_PROXY_SETTINGS = {
    .upstreams = {
        { "8.8.8.8:53", { {}, DEFAULT_UPSTREAM_TIMEOUT, {} } },
        { "8.8.4.4:53", { {}, DEFAULT_UPSTREAM_TIMEOUT, {} } },
    },
    .dns64 = std::nullopt,
    .blocked_response_ttl = 3600,
    .filter_params = {},
    .listeners = {}
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

    std::shared_ptr<with_mtx<std::vector<ag::uint8_vector>>> dns64_prefixes;

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

    ldns_pkt_ptr try_dns64_aaaa_synthesis(upstream_ptr &upstream,
            const ldns_pkt_ptr &request, const ldns_pkt_ptr &response) const;
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

// If we know any DNS64 prefixes, request A RRs from `upstream` and
// return a synthesized AAAA response or nullptr if synthesis was unsuccessful
ldns_pkt_ptr dnsproxy::impl::try_dns64_aaaa_synthesis(upstream_ptr &upstream,
                                                      const ldns_pkt_ptr &request,
                                                      const ldns_pkt_ptr &response) const {
    std::scoped_lock l(this->dns64_prefixes->mtx);

    if (this->dns64_prefixes->val.empty()) {
        // No prefixes
        return nullptr;
    }

    const auto question = ldns_rr_list_rr(ldns_pkt_question(request.get()), 0);
    if (!question || !ldns_rr_owner(question)) {
        dbglog_fid(this->log, request.get(), "DNS64: could not synthesize AAAA response: invalid request");
        return nullptr;
    }

    const ldns_pkt_ptr request_a(
            ldns_pkt_query_new(
                    ldns_rdf_clone(ldns_rr_owner(question)),
                    LDNS_RR_TYPE_A,
                    LDNS_RR_CLASS_IN,
                    0));

    ldns_pkt_set_cd(request_a.get(), ldns_pkt_cd(request.get()));
    ldns_pkt_set_rd(request_a.get(), ldns_pkt_rd(request.get()));

    const auto[response_a, err] = upstream->exchange(request_a.get());
    if (err.has_value()) {
        dbglog_fid(this->log,
                   request.get(),
                   "DNS64: could not synthesize AAAA response: upstream failed to perform A query: {}",
                   err.value().c_str());
        return nullptr;
    }

    const size_t ancount = ldns_pkt_ancount(response_a.get());
    if (ancount == 0) {
        dbglog_fid(this->log,
                   request.get(),
                   "DNS64: could not synthesize AAAA response: upstream returned no A records");
        return nullptr;
    }

    auto aaaa_list = ldns_rr_list_new();
    for (size_t i = 0; i < ancount; ++i) {
        const auto a_rr = ldns_rr_list_rr(ldns_pkt_answer(response_a.get()), i);

        if (LDNS_RR_TYPE_A != ldns_rr_get_type(a_rr)) {
            continue;
        }

        const auto rdf = ldns_rr_rdf(a_rr, 0); // first and only field
        if (!rdf) {
            continue;
        }

        const uint8_view ip4{ldns_rdf_data(rdf), ldns_rdf_size(rdf)};

        for (const auto &pref : this->dns64_prefixes->val) { // assume `dns64_prefixes->mtx` is held
            const auto[ip6, err_synth] = synthesize_ipv4_embedded_ipv6_address({pref.data(), std::size(pref)}, ip4);
            if (err_synth.has_value()) {
                dbglog_fid(this->log,
                           request.get(),
                           "DNS64: could not synthesize IPv4-embedded IPv6: {}",
                           err_synth.value().c_str());
                continue; // Try the next prefix
            }

            const auto aaaa_rr = ldns_rr_clone(a_rr);
            ldns_rr_set_type(aaaa_rr, LDNS_RR_TYPE_AAAA);
            ldns_rdf_deep_free(ldns_rr_pop_rdf(aaaa_rr)); // ip4 view becomes invalid here
            ldns_rr_push_rdf(aaaa_rr, ldns_rdf_new_frm_data(LDNS_RDF_TYPE_AAAA, ip6.size(), ip6.data()));

            ldns_rr_list_push_rr(aaaa_list, aaaa_rr);
        }
    }

    const size_t aaaa_rr_count = ldns_rr_list_rr_count(aaaa_list);
    dbglog_fid(this->log, request.get(), "DNS64: synthesized AAAA RRs: {}", aaaa_rr_count);
    if (aaaa_rr_count > 0) {
        ldns_pkt_ptr aaaa_resp(ldns_pkt_new());

        ldns_pkt_set_id(aaaa_resp.get(), ldns_pkt_id(request.get()));
        ldns_pkt_set_rd(aaaa_resp.get(), ldns_pkt_rd(request.get()));

        ldns_pkt_push_rr_list(aaaa_resp.get(),
                              LDNS_SECTION_QUESTION,
                              ldns_rr_list_clone(ldns_pkt_question(request.get())));

        ldns_pkt_push_rr_list(aaaa_resp.get(), LDNS_SECTION_ANSWER, aaaa_list);

        return aaaa_resp;
    } else {
        ldns_rr_list_free(aaaa_list);
    }

    return nullptr;
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
    for (upstream_settings &us : settings.upstreams) {
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

    proxy->dns64_prefixes = std::make_shared<ag::with_mtx<std::vector<ag::uint8_vector>>>();
    if (settings.dns64.has_value()) {
        infolog(proxy->log, "DNS64 discovery is enabled");

        std::thread prefixes_discovery_thread([uss = settings.dns64.value().upstream,
                                               prefixes = proxy->dns64_prefixes,
                                               logger = proxy->log,
                                               max_tries = settings.dns64.value().max_tries,
                                               wait_time = settings.dns64.value().wait_time]() {
            auto i = max_tries;
            while (i--) {
                std::this_thread::sleep_for(wait_time);

                auto[upstream, err_upstream] = ag::upstream::address_to_upstream(uss.dns_server, uss.options);
                if (err_upstream.has_value()) {
                    dbglog(logger, "DNS64: failed to create DNS64 upstream: {}", err_upstream.value().c_str());
                    continue;
                }

                auto[result, err_prefixes] = ag::discover_dns64_prefixes(upstream);
                if (err_prefixes.has_value()) {
                    dbglog(logger, "DNS64: error discovering prefixes: {}", err_prefixes.value().c_str());
                    continue;
                }

                if (result.empty()) {
                    dbglog(logger, "DNS64: no prefixes discovered, retrying");
                    continue;
                }

                std::scoped_lock l(prefixes->mtx);
                prefixes->val = std::move(result);

                infolog(logger, "DNS64 prefixes discovered: {}", prefixes->val.size());
                return;
            }

            errlog(logger, "DNS64: failed to discover any prefixes");
        });

        prefixes_discovery_thread.detach();
    }

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

std::vector<uint8_t> dnsproxy::handle_message(ag::uint8_view message) {
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
    ldns_pkt_ptr req_holder = ldns_pkt_ptr(request);
    log_packet(proxy->log, request, "client dns request");

    const ldns_rr *question = ldns_rr_list_rr(ldns_pkt_question(request), 0);
    if (question == nullptr) {
        std::string err = ag::utils::fmt_string("Message has no question section");
        dbglog_fid(proxy->log, request, "{}", err.c_str());
        proxy->complete_processed_event(std::move(event), nullptr, nullptr, {}, std::move(err));
        return {};
    }
    auto domain = std::unique_ptr<char, decltype(&free)>(ldns_rdf2str(ldns_rr_owner(question)), free);
    event.domain = domain.get();

    // disable Mozilla DoH
    const ldns_rr_type type = ldns_rr_get_type(question);
    if ((type == LDNS_RR_TYPE_A || type == LDNS_RR_TYPE_AAAA)
            && 0 == strcmp(domain.get(), MOZILLA_DOH_HOST.data())) {
        ldns_pkt_ptr response = ldns_pkt_ptr(proxy->create_nxdomain_response(request));
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
        ldns_pkt_ptr response = ldns_pkt_ptr(proxy->create_blocking_response(request, effective_rules));
        log_packet(proxy->log, response.get(), "rule blocked response");
        std::vector<uint8_t> raw_response = transform_response_to_raw_data(response.get());
        proxy->complete_processed_event(std::move(event), request, response.get(), effective_rules, "");
        return raw_response;
    }

    auto[response, err] = proxy->upstreams[0]->exchange(request);
    event.upstream_addr = proxy->upstreams[0]->address();
    if (err.has_value()) {
        std::string err_str = ag::utils::fmt_string("Upstream failed to perform dns query: %s",
            err.value().c_str());
        errlog_fid(proxy->log, request, "{}" , err_str.c_str());
        proxy->complete_processed_event(std::move(event), request, nullptr, effective_rules, std::move(err_str));
        return {};
    }

    log_packet(proxy->log, response.get(), "upstream dns response");

    if (LDNS_RR_TYPE_AAAA == type
            && LDNS_RCODE_NOERROR == ldns_pkt_get_rcode(response.get())
            && ldns_pkt_ancount(request) == 0) {

        auto synth_response = proxy->try_dns64_aaaa_synthesis(proxy->upstreams[0], req_holder, response);
        if (synth_response) {
            response = std::move(synth_response);
            log_packet(proxy->log, response.get(), "dns64 synthesized response");
        }
    }

    std::vector<uint8_t> raw_response = transform_response_to_raw_data(response.get());
    event.bytes_received = raw_response.size();
    event.bytes_sent = message.size();
    proxy->complete_processed_event(std::move(event), request, response.get(), effective_rules, "");
    return raw_response;
}
