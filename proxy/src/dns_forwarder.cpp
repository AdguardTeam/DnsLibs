#include <thread>

#include <dns_forwarder.h>
#include <ag_utils.h>

#include <ldns/ldns.h>


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


static constexpr std::string_view MOZILLA_DOH_HOST = "use-application-dns.net.";


static void log_packet(const logger &log, const ldns_pkt *packet, const char *pkt_name) {
    if (!log->should_log((spdlog::level::level_enum)DEBUG)) {
        return;
    }

    ldns_buffer *str_dns = ldns_buffer_new(512);
    ldns_status status = ldns_pkt2buffer_str(str_dns, packet);
    if (status != LDNS_STATUS_OK) {
        dbglog_id(log, packet, "Failed to print {}: {} ({})"
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
    std::string mbox = utils::fmt_string("hostmaster.%s",
        (zone != nullptr && strlen(zone) > 0 && zone[0] != '.') ? zone : "");
    free(zone);

    return mbox;
}

// Taken from AdGuardHome/dnsforward.go/genSOA
static ldns_rr *create_soa(const ldns_pkt *request, const dnsproxy_settings *settings) {
    const ldns_rr *question = ldns_rr_list_rr(ldns_pkt_question(request), 0);
    std::string mbox = get_mbox(request);

    ldns_rr *soa = ldns_rr_new();
    assert(soa != nullptr);
    ldns_rr_set_owner(soa, ldns_rdf_clone(ldns_rr_owner(question)));
    ldns_rr_set_ttl(soa, settings->blocked_response_ttl);
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

static ldns_pkt *create_nxdomain_response(const ldns_pkt *request, const dnsproxy_settings *settings) {
    ldns_pkt *response = create_response_by_request(request);
    ldns_pkt_set_rcode(response, LDNS_RCODE_NXDOMAIN);
    ldns_pkt_push_rr(response, LDNS_SECTION_AUTHORITY, create_soa(request, settings));
    return response;
}

static ldns_pkt *create_arecord_response(const ldns_pkt *request, const dnsproxy_settings *settings,
        const dnsfilter::rule **rules) {
    const ldns_rr *question = ldns_rr_list_rr(ldns_pkt_question(request), 0);

    ldns_rr *answer = ldns_rr_new();
    assert(answer != nullptr);
    ldns_rr_set_owner(answer, ldns_rdf_clone(ldns_rr_owner(question)));
    ldns_rr_set_ttl(answer, settings->blocked_response_ttl);
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

static ldns_pkt *create_aaaarecord_response(const ldns_pkt *request, const dnsproxy_settings *settings,
        const dnsfilter::rule **rules) {
    const ldns_rr *question = ldns_rr_list_rr(ldns_pkt_question(request), 0);

    ldns_rr *answer = ldns_rr_new();
    assert(answer != nullptr);
    ldns_rr_set_owner(answer, ldns_rdf_clone(ldns_rr_owner(question)));
    ldns_rr_set_ttl(answer, settings->blocked_response_ttl);
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

static ldns_pkt *create_response_with_ips(const ldns_pkt *request, const dnsproxy_settings *settings,
        const std::vector<const dnsfilter::rule *> &rules) {
    const ldns_rr *question = ldns_rr_list_rr(ldns_pkt_question(request), 0);
    ldns_rr_type type = ldns_rr_get_type(question);
    if (type == LDNS_RR_TYPE_A) {
        const dnsfilter::rule *ipv4_rules[rules.size() + 1];
        std::fill(ipv4_rules, ipv4_rules + rules.size() + 1, nullptr);
        size_t num = 0;
        for (const dnsfilter::rule *r : rules) {
            if (utils::is_valid_ip4(r->ip.value())) {
                ipv4_rules[num++] = r;
            }
        }
        if (num > 0) {
            return create_arecord_response(request, settings, ipv4_rules);
        }
    } else if (type == LDNS_RR_TYPE_AAAA) {
        const dnsfilter::rule *ipv6_rules[rules.size() + 1];
        std::fill(ipv6_rules, ipv6_rules + rules.size() + 1, nullptr);
        size_t num = 0;
        for (const dnsfilter::rule *r : rules) {
            if (!utils::is_valid_ip4(r->ip.value())) {
                ipv6_rules[num++] = r;
            }
        }
        if (num > 0) {
            return create_aaaarecord_response(request, settings, ipv6_rules);
        }
    }
    // empty response
    ldns_pkt *response = create_response_by_request(request);
    ldns_pkt_push_rr(response, LDNS_SECTION_AUTHORITY, create_soa(request, settings));
    return response;
}

static ldns_pkt *create_blocking_response(const ldns_pkt *request, const dnsproxy_settings *settings,
        const std::vector<const dnsfilter::rule *> &rules) {
    const ldns_rr *question = ldns_rr_list_rr(ldns_pkt_question(request), 0);
    ldns_rr_type type = ldns_rr_get_type(question);
    ldns_pkt *response;
    if ((type != LDNS_RR_TYPE_A && type != LDNS_RR_TYPE_AAAA)
            || !rules[0]->ip.has_value()) {
        response = create_nxdomain_response(request, settings);
    } else {
        response = create_response_with_ips(request, settings, rules);
    }
    return response;
}

static ldns_pkt *create_servfail_response(const ldns_pkt *request) {
    ldns_pkt *response = create_response_by_request(request);
    ldns_pkt_set_rcode(response, LDNS_RCODE_SERVFAIL);
    return response;
}

void dns_forwarder::finalize_processed_event(dns_request_processed_event &event,
        const ldns_pkt *request, const ldns_pkt *response,
        const std::vector<const dnsfilter::rule *> &rules) const {
    if (request != nullptr) {
        const ldns_rr *question = ldns_rr_list_rr(ldns_pkt_question(request), 0);
        char *type = ldns_rr_type2str(ldns_rr_get_type(question));
        event.type = type;
        free(type);
    }

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
}

// If we know any DNS64 prefixes, request A RRs from `upstream` and
// return a synthesized AAAA response or nullptr if synthesis was unsuccessful
ldns_pkt_ptr dns_forwarder::try_dns64_aaaa_synthesis(upstream_ptr &upstream, const ldns_pkt_ptr &request,
        const ldns_pkt_ptr &response) const {
    std::scoped_lock l(this->dns64_prefixes->mtx);

    if (this->dns64_prefixes->val.empty()) {
        // No prefixes
        return nullptr;
    }

    const ldns_rr *question = ldns_rr_list_rr(ldns_pkt_question(request.get()), 0);
    if (!question || !ldns_rr_owner(question)) {
        dbglog_fid(log, request.get(), "DNS64: could not synthesize AAAA response: invalid request");
        return nullptr;
    }

    const ldns_pkt_ptr request_a(ldns_pkt_query_new(ldns_rdf_clone(ldns_rr_owner(question)),
        LDNS_RR_TYPE_A, LDNS_RR_CLASS_IN, 0));

    ldns_pkt_set_cd(request_a.get(), ldns_pkt_cd(request.get()));
    ldns_pkt_set_rd(request_a.get(), ldns_pkt_rd(request.get()));

    const auto[response_a, err] = upstream->exchange(request_a.get());
    if (err.has_value()) {
        dbglog_fid(log, request.get(),
            "DNS64: could not synthesize AAAA response: upstream failed to perform A query: {}", err->c_str());
        return nullptr;
    }

    const size_t ancount = ldns_pkt_ancount(response_a.get());
    if (ancount == 0) {
        dbglog_fid(log, request.get(), "DNS64: could not synthesize AAAA response: upstream returned no A records");
        return nullptr;
    }

    ldns_rr_list *aaaa_list = ldns_rr_list_new();
    for (size_t i = 0; i < ancount; ++i) {
        const ldns_rr *a_rr = ldns_rr_list_rr(ldns_pkt_answer(response_a.get()), i);

        if (LDNS_RR_TYPE_A != ldns_rr_get_type(a_rr)) {
            continue;
        }

        const auto rdf = ldns_rr_rdf(a_rr, 0); // first and only field
        if (!rdf) {
            continue;
        }

        const uint8_view ip4{ldns_rdf_data(rdf), ldns_rdf_size(rdf)};

        for (const uint8_vector &pref : this->dns64_prefixes->val) { // assume `dns64_prefixes->mtx` is held
            const auto[ip6, err_synth] = dns64::synthesize_ipv4_embedded_ipv6_address({pref.data(), std::size(pref)}, ip4);
            if (err_synth.has_value()) {
                dbglog_fid(log, request.get(),
                    "DNS64: could not synthesize IPv4-embedded IPv6: {}", err_synth->c_str());
                continue; // Try the next prefix
            }

            ldns_rr *aaaa_rr = ldns_rr_clone(a_rr);
            ldns_rr_set_type(aaaa_rr, LDNS_RR_TYPE_AAAA);
            ldns_rdf_deep_free(ldns_rr_pop_rdf(aaaa_rr)); // ip4 view becomes invalid here
            ldns_rr_push_rdf(aaaa_rr, ldns_rdf_new_frm_data(LDNS_RDF_TYPE_AAAA, ip6.size(), ip6.data()));

            ldns_rr_list_push_rr(aaaa_list, aaaa_rr);
        }
    }

    const size_t aaaa_rr_count = ldns_rr_list_rr_count(aaaa_list);
    dbglog_fid(log, request.get(), "DNS64: synthesized AAAA RRs: {}", aaaa_rr_count);
    if (aaaa_rr_count == 0) {
        ldns_rr_list_free(aaaa_list);
        return nullptr;
    }

    ldns_pkt *aaaa_resp = ldns_pkt_new();
    ldns_pkt_set_id(aaaa_resp, ldns_pkt_id(request.get()));
    ldns_pkt_set_rd(aaaa_resp, ldns_pkt_rd(request.get()));
    ldns_pkt_push_rr_list(aaaa_resp, LDNS_SECTION_QUESTION, ldns_rr_list_clone(ldns_pkt_question(request.get())));
    ldns_pkt_push_rr_list(aaaa_resp, LDNS_SECTION_ANSWER, aaaa_list);

    return ldns_pkt_ptr(aaaa_resp);
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


dns_forwarder::dns_forwarder() = default;

dns_forwarder::~dns_forwarder() = default;

bool dns_forwarder::init(const dnsproxy_settings &settings) {
    this->log = create_logger("DNS forwarder");
    infolog(log, "Initializing forwarder...");

    this->settings = &settings;

    infolog(log, "Initializing upstreams...");
    this->upstreams.reserve(settings.upstreams.size());
    for (const upstream_settings &us : settings.upstreams) {
        infolog(log, "Initializing upstream {}...", us.dns_server);
        auto[upstream, err] = upstream::address_to_upstream(us.dns_server, us.options);
        if (err.has_value()) {
            errlog(log, "Failed to create upstream: {}", err.value());
        } else {
            this->upstreams.emplace_back(std::move(upstream));
            infolog(log, "Upstream created successfully");
        }
    }
    if (this->upstreams.empty()) {
        errlog(log, "Failed to initialized any upstream");
        this->deinit();
        return false;
    }
    infolog(log, "Upstreams initialized");

    infolog(log, "Initializing filtering module...");
    std::optional<dnsfilter::handle> handle = this->filter.create(settings.filter_params);
    if (!handle.has_value()) {
        errlog(log, "Failed to initialize filtering module");
        this->deinit();
        return false;
    }
    this->filter_handle = handle.value();
    infolog(log, "Filtering module initialized");

    this->dns64_prefixes = std::make_shared<ag::with_mtx<std::vector<ag::uint8_vector>>>();
    if (settings.dns64.has_value()) {
        infolog(log, "DNS64 discovery is enabled");

        std::thread prefixes_discovery_thread(
            [uss = settings.dns64.value().upstream,
                    prefixes = this->dns64_prefixes,
                    logger = this->log,
                    max_tries = settings.dns64->max_tries,
                    wait_time = settings.dns64->wait_time]() {
                auto i = max_tries;
                while (i--) {
                    std::this_thread::sleep_for(wait_time);

                    auto[upstream, err_upstream] = ag::upstream::address_to_upstream(uss.dns_server, uss.options);
                    if (err_upstream.has_value()) {
                        dbglog(logger, "DNS64: failed to create DNS64 upstream: {}", err_upstream->c_str());
                        continue;
                    }

                    auto[result, err_prefixes] = ag::dns64::discover_prefixes(upstream);
                    if (err_prefixes.has_value()) {
                        dbglog(logger, "DNS64: error discovering prefixes: {}", err_prefixes->c_str());
                        continue;
                    }

                    if (result.empty()) {
                        dbglog(logger, "DNS64: no prefixes discovered, retrying");
                        continue;
                    }

                    std::scoped_lock l(prefixes->mtx);
                    prefixes->val = std::move(result);

                    infolog(logger, "DNS64 prefixes discovered: {}", prefixes->val.size());
                }

                errlog(logger, "DNS64: failed to discover any prefixes");
            }
        );

        prefixes_discovery_thread.detach();
    }

    infolog(log, "Forwarder initialized");
    return true;
}

void dns_forwarder::deinit() {
    this->settings = nullptr;
    this->upstreams.clear();
    this->filter.destroy(this->filter_handle);
}

dns_forwarder::result dns_forwarder::handle_message(uint8_view message, dns_request_processed_event &event) {
    ldns_pkt *request;
    ldns_status status = ldns_wire2pkt(&request, message.data(), message.length());
    if (status != LDNS_STATUS_OK) {
        std::string err = utils::fmt_string("Failed to parse payload: %s (%d)",
            ldns_get_errorstr_by_id(status), status);
        dbglog(log, "{} {}", __func__, err);
        finalize_processed_event(event, nullptr, nullptr, {});
        // @todo: think out what to do in this case
        return { {}, std::move(err) };
    }
    ldns_pkt_ptr req_holder = ldns_pkt_ptr(request);
    log_packet(log, request, "Client dns request");

    const ldns_rr *question = ldns_rr_list_rr(ldns_pkt_question(request), 0);
    if (question == nullptr) {
        std::string err = "Message has no question section";
        dbglog_fid(log, request, "{}", err);
        ldns_pkt_ptr response(create_servfail_response(request));
        log_packet(log, response.get(), "Server failure response");
        finalize_processed_event(event, nullptr, response.get(), {});
        std::vector<uint8_t> raw_response = transform_response_to_raw_data(response.get());
        return { std::move(raw_response), std::move(err) };
    }
    auto domain = allocated_ptr<char>(ldns_rdf2str(ldns_rr_owner(question)));
    event.domain = domain.get();

    // disable Mozilla DoH
    const ldns_rr_type type = ldns_rr_get_type(question);
    if ((type == LDNS_RR_TYPE_A || type == LDNS_RR_TYPE_AAAA)
            && 0 == strcmp(domain.get(), MOZILLA_DOH_HOST.data())) {
        ldns_pkt_ptr response(create_nxdomain_response(request, this->settings));
        log_packet(log, response.get(), "Mozilla DOH blocking response");
        std::vector<uint8_t> raw_response = transform_response_to_raw_data(response.get());
        finalize_processed_event(event, request, response.get(), {});
        return { std::move(raw_response), std::nullopt };
    }

    std::string_view pure_domain = domain.get();
    if (ldns_dname_str_absolute(domain.get())) {
        pure_domain.remove_suffix(1); // drop trailing dot
    }
    tracelog_fid(log, request, "Query domain: {}", pure_domain);

    std::vector<dnsfilter::rule> rules = this->filter.match(this->filter_handle, pure_domain);
    for (const dnsfilter::rule &rule : rules) {
        tracelog_fid(log, request, "Matched rule: {}", rule.text);
    }

    std::vector<const dnsfilter::rule *> effective_rules = dnsfilter::get_effective_rules(rules);
    if (effective_rules.size() > 0
            && !effective_rules[0]->props.test(dnsfilter::RP_EXCEPTION)) {
        dbglog_fid(log, request, "DNS query blocked by rule: {}", effective_rules[0]->text);
        ldns_pkt_ptr response(create_blocking_response(request, this->settings, effective_rules));
        log_packet(log, response.get(), "Rule blocked response");
        std::vector<uint8_t> raw_response = transform_response_to_raw_data(response.get());
        finalize_processed_event(event, request, response.get(), effective_rules);
        return { std::move(raw_response), std::nullopt };
    }

    // @todo: upstream selection algorithm
    auto[response, err] = this->upstreams[0]->exchange(request);
    event.upstream_addr = this->upstreams[0]->address();
    if (err.has_value()) {
        std::string err_str = utils::fmt_string("Upstream failed to perform dns query: %s", err->c_str());
        dbglog_fid(log, request, "{}", err_str);
        response = ldns_pkt_ptr(create_servfail_response(request));
        log_packet(log, response.get(), "Server failure response");
        std::vector<uint8_t> raw_response = transform_response_to_raw_data(response.get());
        finalize_processed_event(event, request, response.get(), effective_rules);
        return { std::move(raw_response), std::move(err_str) };
    }

    log_packet(log, response.get(), "Upstream dns response");

    if (LDNS_RR_TYPE_AAAA == type
            && LDNS_RCODE_NOERROR == ldns_pkt_get_rcode(response.get())
            && ldns_pkt_ancount(response.get()) == 0) {
        ldns_pkt_ptr synth_response = try_dns64_aaaa_synthesis(this->upstreams[0], req_holder, response);
        if (synth_response != nullptr) {
            response = std::move(synth_response);
            log_packet(log, response.get(), "DNS64 synthesized response");
        }
    }

    std::vector<uint8_t> raw_response = transform_response_to_raw_data(response.get());
    event.bytes_received = raw_response.size();
    event.bytes_sent = message.size();
    finalize_processed_event(event, request, response.get(), effective_rules);
    return { std::move(raw_response), std::nullopt };
}
