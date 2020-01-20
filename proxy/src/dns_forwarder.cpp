#include <thread>

#include <dns_forwarder.h>
#include <default_verifier.h>
#include <ag_utils.h>
#include <ag_cache.h>
#include <string>
#include <cstring>

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

// An ldns_buffer grows automatically.
// We set the initial capacity so that most responses will fit without reallocations.
static constexpr size_t RESPONSE_BUFFER_INITIAL_CAPACITY = 512;

static constexpr uint32_t SOA_RETRY_DEFAULT = 900;
static constexpr uint32_t SOA_RETRY_IPV6_BLOCK = 60;

static std::string get_cache_key(const ldns_pkt *request) {
    const auto *question = ldns_rr_list_rr(ldns_pkt_question(request), 0);
    std::string key = fmt::format("{}|{}|{}{}|", // '|' is to avoid collisions
                                  ldns_rr_get_type(question),
                                  ldns_rr_get_class(question),
                                  ldns_pkt_edns_do(request) ? "1" : "0",
                                  ldns_pkt_cd(request) ? "1" : "0");

    // Compute the domain name, in lower case for case-insensitivity
    const auto *owner = ldns_rr_owner(question);
    const size_t size = ldns_rdf_size(owner);
    key.reserve(key.size() + size);
    if (size == 1) {
        key.push_back('.');
    } else {
        auto *data = (uint8_t *) ldns_rdf_data(owner);
        uint8_t len = data[0];
        uint8_t src_pos = 0;
        while ((len > 0) && (src_pos < size)) {
            ++src_pos;
            for (int_fast32_t i = 0; i < len; ++i) {
                key.push_back(std::tolower(data[src_pos]));
                ++src_pos;
            }
            if (src_pos < size) {
                key.push_back('.');
            }
            len = data[src_pos];
        }
    }

    return key;
}

struct dns_forwarder::application_verifier : public certificate_verifier {
    const dnsproxy_events *events = nullptr;

    explicit application_verifier(const dnsproxy_events *events)
        : events(events)
    {}

    static std::optional<std::vector<uint8_t>> serialize_certificate(X509 *cert) {
        std::vector<uint8_t> out;
        if (int len = i2d_X509(cert, nullptr); len <= 0) {
            return std::nullopt;
        } else {
            out.resize(len);
        }
        unsigned char *buffer = (unsigned char *)out.data();
        i2d_X509(cert, (unsigned char **)&buffer);
        return out;
    }

    err_string verify(X509_STORE_CTX *ctx, std::string_view host) const override {
        if (err_string err = verify_host_name(X509_STORE_CTX_get0_cert(ctx), host); err.has_value()) {
            return err;
        }

        certificate_verification_event event = {};

        std::optional<std::vector<uint8_t>> serialized = serialize_certificate(X509_STORE_CTX_get0_cert(ctx));
        if (!serialized.has_value()) {
            return "Failed to serialize certificate";
        }
        event.certificate = std::move(serialized.value());

        STACK_OF(X509) *chain = X509_STORE_CTX_get0_untrusted(ctx);
        event.chain.reserve(sk_X509_num(chain));
        for (size_t i = 0; i < sk_X509_num(chain); ++i) {
            X509 *cert = sk_X509_value(chain, i);
            serialized = serialize_certificate(cert);
            if (serialized.has_value()) {
                event.chain.emplace_back(std::move(serialized.value()));
            } else {
                event.chain.clear();
                break;
            }
        }

        return this->events->on_certificate_verification(std::move(event));
    }
};


static void log_packet(const logger &log, const ldns_pkt *packet, const char *pkt_name) {
    if (!log->should_log((spdlog::level::level_enum)DEBUG)) {
        return;
    }

    ldns_buffer *str_dns = ldns_buffer_new(RESPONSE_BUFFER_INITIAL_CAPACITY);
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
    std::string mbox = AG_FMT("hostmaster.{}",
        (zone != nullptr && strlen(zone) > 0 && zone[0] != '.') ? zone : "");
    free(zone);

    return mbox;
}

// Taken from AdGuardHome/dnsforward.go/genSOA
static ldns_rr *create_soa(const ldns_pkt *request, const dnsproxy_settings *settings, uint32_t retry_secs) {
    const ldns_rr *question = ldns_rr_list_rr(ldns_pkt_question(request), 0);
    std::string mbox = get_mbox(request);

    ldns_rr *soa = ldns_rr_new();
    assert(soa != nullptr);
    ldns_rr_set_owner(soa, ldns_rdf_clone(ldns_rr_owner(question)));
    ldns_rr_set_ttl(soa, settings->blocked_response_ttl_secs);
    ldns_rr_set_type(soa, LDNS_RR_TYPE_SOA);
    ldns_rr_set_class(soa, LDNS_RR_CLASS_IN);
    // fill soa rdata
    ldns_rr_push_rdf(soa, ldns_dname_new_frm_str("fake-for-negative-caching.adguard.com.")); // MNAME
    ldns_rr_push_rdf(soa, ldns_dname_new_frm_str(mbox.c_str())); // RNAME
    ldns_rr_push_rdf(soa, ldns_native2rdf_int32(LDNS_RDF_TYPE_TIME, time(nullptr) + 100500)); // SERIAL
    ldns_rr_push_rdf(soa, ldns_native2rdf_int32(LDNS_RDF_TYPE_PERIOD, 1800)); // REFRESH
    ldns_rr_push_rdf(soa, ldns_native2rdf_int32(LDNS_RDF_TYPE_PERIOD, retry_secs)); // RETRY
    ldns_rr_push_rdf(soa, ldns_native2rdf_int32(LDNS_RDF_TYPE_PERIOD, 604800)); // EXPIRE
    ldns_rr_push_rdf(soa, ldns_native2rdf_int32(LDNS_RDF_TYPE_PERIOD, 86400)); // MINIMUM
    return soa;
}

static ldns_pkt *create_nxdomain_response(const ldns_pkt *request, const dnsproxy_settings *settings) {
    ldns_pkt *response = create_response_by_request(request);
    ldns_pkt_set_rcode(response, LDNS_RCODE_NXDOMAIN);
    ldns_pkt_push_rr(response, LDNS_SECTION_AUTHORITY, create_soa(request, settings, 900));
    return response;
}

static ldns_pkt *create_soa_response(const ldns_pkt *request, const dnsproxy_settings *settings, uint32_t retry_secs) {
    ldns_pkt *response = create_response_by_request(request);
    ldns_pkt_set_rcode(response, LDNS_RCODE_NOERROR);
    ldns_pkt_push_rr(response, LDNS_SECTION_AUTHORITY, create_soa(request, settings, retry_secs));
    return response;
}

static ldns_pkt *create_arecord_response(const ldns_pkt *request, const dnsproxy_settings *settings,
        const dnsfilter::rule **rules) {
    const ldns_rr *question = ldns_rr_list_rr(ldns_pkt_question(request), 0);

    ldns_rr *answer = ldns_rr_new();
    assert(answer != nullptr);
    ldns_rr_set_owner(answer, ldns_rdf_clone(ldns_rr_owner(question)));
    ldns_rr_set_ttl(answer, settings->blocked_response_ttl_secs);
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
    ldns_rr_set_ttl(answer, settings->blocked_response_ttl_secs);
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
    return create_soa_response(request, settings, SOA_RETRY_DEFAULT);
}

static ldns_pkt *create_unspec_or_custom_address_response(const ldns_pkt *request, const dnsproxy_settings *settings) {
    ldns_rr *question = ldns_rr_list_rr(ldns_pkt_question(request), 0);
    ldns_rr_type type = ldns_rr_get_type(question);
    assert(type == LDNS_RR_TYPE_A || type == LDNS_RR_TYPE_AAAA);

    if (settings->blocking_mode == dnsproxy_blocking_mode::CUSTOM_ADDRESS) {
        if (type == LDNS_RR_TYPE_A && settings->custom_blocking_ipv4.empty()) {
            return create_soa_response(request, settings, SOA_RETRY_DEFAULT);
        } else if (type == LDNS_RR_TYPE_AAAA && settings->custom_blocking_ipv6.empty()) {
            return create_soa_response(request, settings, SOA_RETRY_DEFAULT);
        }
    }

    ldns_rr *rr = ldns_rr_new();
    ldns_rr_set_owner(rr, ldns_rdf_clone(ldns_rr_owner(question)));
    ldns_rr_set_ttl(rr, settings->blocked_response_ttl_secs);
    ldns_rr_set_type(rr, type);
    ldns_rr_set_class(rr, ldns_rr_get_class(question));

    if (type == LDNS_RR_TYPE_A) {
        if (settings->blocking_mode == dnsproxy_blocking_mode::CUSTOM_ADDRESS) {
            assert(utils::is_valid_ip4(settings->custom_blocking_ipv4));
            ldns_rr_push_rdf(rr, ldns_rdf_new_frm_str(LDNS_RDF_TYPE_A, settings->custom_blocking_ipv4.c_str()));
        } else {
            ldns_rr_push_rdf(rr, ldns_rdf_new_frm_str(LDNS_RDF_TYPE_A, "0.0.0.0"));
        }
    } else {
        if (settings->blocking_mode == dnsproxy_blocking_mode::CUSTOM_ADDRESS) {
            assert(utils::is_valid_ip6(settings->custom_blocking_ipv6));
            ldns_rr_push_rdf(rr, ldns_rdf_new_frm_str(LDNS_RDF_TYPE_AAAA, settings->custom_blocking_ipv6.c_str()));
        } else {
            ldns_rr_push_rdf(rr, ldns_rdf_new_frm_str(LDNS_RDF_TYPE_AAAA, "::"));
        }
    }

    ldns_pkt *response = create_response_by_request(request);
    ldns_pkt_push_rr(response, LDNS_SECTION_ANSWER, rr);
    return response;
}

// Whether the given set of rules contains IPs considered "blocking",
// i.e. the proxy must respond with a blocking response according to the blocking_mode
static bool rules_contain_blocking_ip(const std::vector<const dnsfilter::rule *> &rules) {
    static const ag::hash_set<std::string> BLOCKING_IPS = {"0.0.0.0", "127.0.0.1", "::", "::1", "[::]", "[::1]"};
    for (const auto &rule : rules) {
        if (rule->ip && BLOCKING_IPS.count(*rule->ip)) {
            return true;
        }
    }
    return false;
}

static ldns_pkt *create_blocking_response(const ldns_pkt *request, const dnsproxy_settings *settings,
        const std::vector<const dnsfilter::rule *> &rules) {
    const ldns_rr *question = ldns_rr_list_rr(ldns_pkt_question(request), 0);
    ldns_rr_type type = ldns_rr_get_type(question);
    ldns_pkt *response;
    if (type != LDNS_RR_TYPE_A && type != LDNS_RR_TYPE_AAAA) { // Can only respond with NXDOMAIN or NOERROR+SOA
        response = (settings->blocking_mode == dnsproxy_blocking_mode::NXDOMAIN)
                   ? create_nxdomain_response(request, settings)
                   : create_soa_response(request, settings, SOA_RETRY_IPV6_BLOCK);
    } else if (!rules[0]->ip.has_value()) { // Adblock-style rule
        response = (settings->blocking_mode == dnsproxy_blocking_mode::UNSPECIFIED_ADDRESS
                    || settings->blocking_mode == dnsproxy_blocking_mode::CUSTOM_ADDRESS)
                   ? create_unspec_or_custom_address_response(request, settings)
                   : create_nxdomain_response(request, settings);
    } else if (rules_contain_blocking_ip(rules)) { // hosts-style blocking rule
        response = (settings->blocking_mode == dnsproxy_blocking_mode::NXDOMAIN)
                   ? create_nxdomain_response(request, settings)
                   : create_unspec_or_custom_address_response(request, settings);
    } else { // hosts-style custom IP rule
        response = create_response_with_ips(request, settings, rules);
    }
    return response;
}

static ldns_pkt *create_servfail_response(const ldns_pkt *request) {
    ldns_pkt *response = create_response_by_request(request);
    ldns_pkt_set_rcode(response, LDNS_RCODE_SERVFAIL);
    return response;
}

static void set_event_rules(dns_request_processed_event &event, const std::vector<const dnsfilter::rule *> &rules) {
    event.rules.clear();
    event.rules.reserve(rules.size());

    event.filter_list_ids.clear();
    event.filter_list_ids.reserve(rules.size());

    for (const dnsfilter::rule *rule : rules) {
        event.rules.push_back(rule->text);
        event.filter_list_ids.push_back(rule->filter_id);
    }

    event.whitelist = rules.size() > 0 && rules[0]->props.test(dnsfilter::RP_EXCEPTION);
}

/**
 * Format RR list using the following format:
 * <Type>, <RDFs, space separated>\n
 * e.g.:
 * A, 1.2.3.4
 * AAAA, 12::34
 * CNAME, google.com.
 */
static std::string rr_list_to_string(const ldns_rr_list *rr_list) {
    if (rr_list == nullptr) {
        return {};
    }
    ag::allocated_ptr<char> answer(ldns_rr_list2str(rr_list));
    if (answer == nullptr) {
        return {};
    }
    std::string_view answer_view = answer.get();
    std::string out;
    out.reserve(answer_view.size());
    auto answer_parts = ag::utils::split_by(answer_view, '\t');
    auto it = answer_parts.begin();
    if (answer_parts.size() >= 4) {
        it++; // Skip owner
        it++; // Skip ttl
        it++; // Skip class
        out += *it++; // Add type
        out += ',';
        // Add serialized RDFs
        while (it != answer_parts.end()) {
            out += ' ';
            out += *it++;
        }
    }
    return out;
}

void dns_forwarder::finalize_processed_event(dns_request_processed_event &event, const ldns_pkt *request,
                                             const ldns_pkt *response, const ldns_pkt *original_response,
                                             const upstream *upstream, err_string error) const {
    if (request != nullptr) {
        const ldns_rr *question = ldns_rr_list_rr(ldns_pkt_question(request), 0);
        char *type = ldns_rr_type2str(ldns_rr_get_type(question));
        event.type = type;
        free(type);
    } else {
        event.type.clear();
    }

    if (response != nullptr) {
        auto status = ag::allocated_ptr<char>(ldns_pkt_rcode2str(ldns_pkt_get_rcode(response)));
        event.status = status != nullptr ? status.get() : "";
        event.answer = rr_list_to_string(ldns_pkt_answer(response));
    } else {
        event.status.clear();
        event.answer.clear();
    }

    if (original_response != nullptr) {
        event.original_answer = rr_list_to_string(ldns_pkt_answer(original_response));
    } else {
        event.original_answer.clear();
    }

    if (upstream != nullptr) {
        event.upstream_addr = upstream->opts.address;
    } else {
        event.upstream_addr.clear();
    }

    if (error.has_value()) {
        event.error = std::move(error.value());
    } else {
        event.error.clear();
    }

    event.elapsed = duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count() - event.start_time;
    if (this->events->on_request_processed != nullptr) {
        this->events->on_request_processed(event);
    }
}

// If we know any DNS64 prefixes, request A RRs from `upstream` and
// return a synthesized AAAA response or nullptr if synthesis was unsuccessful
ldns_pkt_ptr dns_forwarder::try_dns64_aaaa_synthesis(upstream *upstream, const ldns_pkt_ptr &request,
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

    ldns_rr_list_deep_free(ldns_pkt_question(aaaa_resp));
    ldns_pkt_set_qdcount(aaaa_resp, ldns_pkt_qdcount(request.get()));
    ldns_pkt_set_question(aaaa_resp, ldns_pkt_get_section_clone(request.get(), LDNS_SECTION_QUESTION));

    ldns_rr_list_deep_free(ldns_pkt_answer(aaaa_resp));
    ldns_pkt_set_ancount(aaaa_resp, aaaa_rr_count);
    ldns_pkt_set_answer(aaaa_resp, aaaa_list);

    return ldns_pkt_ptr(aaaa_resp);
}

static std::vector<uint8_t> transform_response_to_raw_data(const ldns_pkt *message) {
    ldns_buffer *buffer = ldns_buffer_new(RESPONSE_BUFFER_INITIAL_CAPACITY);
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

bool dns_forwarder::init(const dnsproxy_settings &settings, const dnsproxy_events &events) {
    this->log = create_logger("DNS forwarder");
    infolog(log, "Initializing forwarder...");

    this->settings = &settings;
    this->events = &events;

    if (settings.blocking_mode == dnsproxy_blocking_mode::CUSTOM_ADDRESS) {
        // Check custom IPv4
        if (settings.custom_blocking_ipv4.empty()) {
            warnlog(this->log, "Custom blocking IPv4 not set: blocking responses to A queries will be empty");
        } else if (!utils::is_valid_ip4(settings.custom_blocking_ipv4)) {
            errlog(this->log, "Invalid custom blocking IPv4 address: {}", settings.custom_blocking_ipv4);
            return false;
        }
        // Check custom IPv6
        if (settings.custom_blocking_ipv6.empty()) {
            warnlog(this->log, "Custom blocking IPv6 not set: blocking responses to AAAA queries will be empty");
        } else if (!utils::is_valid_ip6(settings.custom_blocking_ipv6)) {
            errlog(this->log, "Invalid custom blocking IPv6 address: {}", settings.custom_blocking_ipv6);
            return false;
        }
    }

    if (events.on_certificate_verification != nullptr) {
        dbglog(log, "Using application_verifier");
        this->cert_verifier = std::make_shared<application_verifier>(this->events);
    } else {
        dbglog(log, "Using default_verifier");
        this->cert_verifier = std::make_shared<default_verifier>();
    }

    infolog(log, "Initializing upstreams...");
    upstream_factory us_factory({ this->cert_verifier.get(), this->settings->ipv6_available });
    this->upstreams.reserve(settings.upstreams.size());
    for (const upstream::options &options : settings.upstreams) {
        infolog(log, "Initializing upstream {}...", options.address);
        auto[upstream, err] = us_factory.create_upstream(options);
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

    this->dns64_prefixes = std::make_shared<with_mtx<std::vector<uint8_vector>>>();
    if (settings.dns64.has_value()) {
        infolog(log, "DNS64 discovery is enabled");

        std::thread prefixes_discovery_thread([uss = settings.dns64->upstreams,
                                               verifier = this->cert_verifier,
                                               prefixes = this->dns64_prefixes,
                                               logger = this->log,
                                               max_tries = settings.dns64->max_tries,
                                               wait_time = settings.dns64->wait_time]() {
                upstream_factory us_factory({ verifier.get() });
                auto i = max_tries;
                while (i--) {
                    std::this_thread::sleep_for(wait_time);
                    for (auto &us : uss) {
                        auto[upstream, err_upstream] = us_factory.create_upstream(us);
                        if (err_upstream.has_value()) {
                            dbglog(logger, "DNS64: failed to create DNS64 upstream: {}", err_upstream->c_str());
                            continue;
                        }

                        auto[result, err_prefixes] = dns64::discover_prefixes(upstream);
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
                        return;
                    }
                }

                errlog(logger, "DNS64: failed to discover any prefixes");
            }
        );

        prefixes_discovery_thread.detach();
    }

    {
        std::scoped_lock l(this->response_cache.mtx);
        this->response_cache.val.set_capacity(this->settings->dns_cache_size);
    }

    infolog(log, "Forwarder initialized");
    return true;
}

void dns_forwarder::deinit() {
    this->settings = nullptr;
    this->upstreams.clear();
    this->filter.destroy(this->filter_handle);
    {
        std::scoped_lock l(this->response_cache.mtx);
        this->response_cache.val.clear();
    }
}

// Returns a response synthesized from the cached template, or nullptr if no cache entry satisfies the given key
ldns_pkt_ptr dns_forwarder::create_response_from_cache(const std::string &key, const ldns_pkt *request) {
    if (!this->settings->dns_cache_size) {
        // Caching disabled
        return nullptr;
    }

    ldns_pkt_ptr response = nullptr;
    uint32_t ttl = 0;
    {
        std::shared_lock l(this->response_cache.mtx);
        auto &cache = this->response_cache.val;

        auto cached_response_acc = cache.get(key);
        if (!cached_response_acc) {
            return nullptr;
        }

        auto cached_response_ttl = duration_cast<seconds>(cached_response_acc->expires_at - ag::steady_clock::now());
        if (cached_response_ttl.count() <= 0) {
            cache.make_lru(cached_response_acc);
            return nullptr;
        }

        ttl = cached_response_ttl.count();
        response.reset(ldns_pkt_clone(cached_response_acc->response.get()));
    }

    // Patch response id
    ldns_pkt_set_id(response.get(), ldns_pkt_id(request));

    // Patch response question section
    assert(!ldns_pkt_question(response.get()));
    ldns_pkt_set_qdcount(response.get(), ldns_pkt_qdcount(request));
    ldns_pkt_set_question(response.get(), ldns_pkt_get_section_clone(request, LDNS_SECTION_QUESTION));

    // Patch response TTLs
    for (int_fast32_t i = 0; i < ldns_pkt_ancount(response.get()); ++i) {
        ldns_rr_set_ttl(ldns_rr_list_rr(ldns_pkt_answer(response.get()), i), ttl);
    }

    return response;
}

uint32_t compute_min_rr_ttl(const ldns_pkt *pkt) {
    uint32_t min_rr_ttl = UINT32_MAX;
    for (int_fast32_t i = 0; i < ldns_pkt_ancount(pkt); ++i) {
        min_rr_ttl = std::min(min_rr_ttl, ldns_rr_ttl(ldns_rr_list_rr(ldns_pkt_answer(pkt), i)));
    }
    for (int_fast32_t i = 0; i < ldns_pkt_arcount(pkt); ++i) {
        min_rr_ttl = std::min(min_rr_ttl, ldns_rr_ttl(ldns_rr_list_rr(ldns_pkt_additional(pkt), i)));
    }
    for (int_fast32_t i = 0; i < ldns_pkt_nscount(pkt); ++i) {
        min_rr_ttl = std::min(min_rr_ttl, ldns_rr_ttl(ldns_rr_list_rr(ldns_pkt_authority(pkt), i)));
    }
    if (min_rr_ttl == UINT32_MAX) { // No RRs in pkt (or insanely large TTL)
        min_rr_ttl = 0;
    }
    return min_rr_ttl;
}

// Checks cacheability and puts an eligible response to the cache
void dns_forwarder::put_response_to_cache(std::string key, ldns_pkt_ptr response) {
    if (!this->settings->dns_cache_size) {
        // Caching disabled
        return;
    }

    if (ldns_pkt_tc(response.get()) // Truncated
        || ldns_pkt_qdcount(response.get()) != 1 // Invalid
        || ldns_pkt_get_rcode(response.get()) != LDNS_RCODE_NOERROR // Error
        ) {
        // Not cacheable
        return;
    }

    const auto *question = ldns_rr_list_rr(ldns_pkt_question(response.get()), 0);
    const auto type = ldns_rr_get_type(question);
    if (type == LDNS_RR_TYPE_A || type == LDNS_RR_TYPE_AAAA) {
        // Check contains at least one record of requested type
        bool found = false;
        for (int_fast32_t i = 0; i < ldns_pkt_ancount(response.get()); ++i) {
            const ldns_rr *rr = ldns_rr_list_rr(ldns_pkt_answer(response.get()), 0);
            if (rr && ldns_rr_get_type(rr) == type) {
                found = true;
                break;
            }
        }
        if (!found) {
            // Not cacheable
            return;
        }
    }

    // Will be patched when returning the cached response
    ldns_rr_list_deep_free(ldns_pkt_question(response.get()));
    ldns_pkt_set_question(response.get(), nullptr);
    ldns_pkt_set_qdcount(response.get(), 0);

    // This is NOT an authoritative answer
    ldns_pkt_set_aa(response.get(), false);

    // Compute the TTL of the cached response as the minimum of the response RR's TTLs
    uint32_t min_rr_ttl = compute_min_rr_ttl(response.get());
    if (min_rr_ttl == 0) {
        // Not cacheable
        return;
    }

    cached_response cached_response{
        .response = std::move(response),
        .expires_at = ag::steady_clock::now() + seconds(min_rr_ttl),
    };

    std::unique_lock l(this->response_cache.mtx);
    auto &cache = this->response_cache.val;
    cache.insert(std::move(key), std::move(cached_response));
}

std::vector<uint8_t> dns_forwarder::handle_message(uint8_view message) {
    dns_request_processed_event event = {};
    event.start_time = duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();

    ldns_pkt *request;
    ldns_status status = ldns_wire2pkt(&request, message.data(), message.length());
    if (status != LDNS_STATUS_OK) {
        std::string err = AG_FMT("Failed to parse payload: {} ({})",
            ldns_get_errorstr_by_id(status), status);
        dbglog(log, "{} {}", __func__, err);
        finalize_processed_event(event, nullptr, nullptr, nullptr, nullptr, std::move(err));
        // @todo: think out what to do in this case
        return {};
    }
    ldns_pkt_ptr req_holder = ldns_pkt_ptr(request);
    log_packet(log, request, "Client dns request");

    const ldns_rr *question = ldns_rr_list_rr(ldns_pkt_question(request), 0);
    if (question == nullptr) {
        std::string err = "Message has no question section";
        dbglog_fid(log, request, "{}", err);
        ldns_pkt_ptr response(create_servfail_response(request));
        log_packet(log, response.get(), "Server failure response");
        finalize_processed_event(event, nullptr, response.get(), nullptr, nullptr, std::move(err));
        std::vector<uint8_t> raw_response = transform_response_to_raw_data(response.get());
        return raw_response;
    }

    std::string cache_key = get_cache_key(request);

    if (auto cached_response = create_response_from_cache(cache_key, request)) {
        dbglog_fid(log, request, "Cached response found");
        log_packet(log, cached_response.get(), "Cached response");
        event.cache_hit = true;
        std::vector<uint8_t> raw_response = transform_response_to_raw_data(cached_response.get());
        finalize_processed_event(event, request, cached_response.get(), nullptr, nullptr, std::nullopt);
        return raw_response;
    }

    auto domain = allocated_ptr<char>(ldns_rdf2str(ldns_rr_owner(question)));
    event.domain = domain.get();

    const ldns_rr_type type = ldns_rr_get_type(question);

    // IPv6 blocking
    if (this->settings->block_ipv6 && LDNS_RR_TYPE_AAAA == type) {
        dbglog_fid(log, request, "AAAA DNS query blocked because IPv6 blocking is enabled");
        ldns_pkt_ptr response(create_soa_response(request, this->settings, SOA_RETRY_IPV6_BLOCK));
        log_packet(log, response.get(), "IPv6 blocking response");
        std::vector<uint8_t> raw_response = transform_response_to_raw_data(response.get());
        finalize_processed_event(event, request, response.get(), nullptr, nullptr, std::nullopt);
        return raw_response;
    }

    // disable Mozilla DoH
    if ((type == LDNS_RR_TYPE_A || type == LDNS_RR_TYPE_AAAA)
            && 0 == strcmp(domain.get(), MOZILLA_DOH_HOST.data())) {
        ldns_pkt_ptr response(create_nxdomain_response(request, this->settings));
        log_packet(log, response.get(), "Mozilla DOH blocking response");
        std::vector<uint8_t> raw_response = transform_response_to_raw_data(response.get());
        finalize_processed_event(event, request, response.get(), nullptr, nullptr, std::nullopt);
        return raw_response;
    }

    std::string_view pure_domain = domain.get();
    if (ldns_dname_str_absolute(domain.get())) {
        pure_domain.remove_suffix(1); // drop trailing dot
    }
    tracelog_fid(log, request, "Query domain: {}", pure_domain);

    if (auto raw_blocking_response = apply_filter(pure_domain, request, nullptr, event)) {
        return *raw_blocking_response;
    }

    ldns_pkt_ptr response = nullptr;
    upstream *successful_upstream = nullptr;
    for (auto i = this->upstreams.begin(); i != this->upstreams.end(); ++i) {
        upstream_ptr &upstream = *i;
        upstream::exchange_result result = upstream->exchange(request);
        if (!result.error.has_value()) {
            successful_upstream = upstream.get();
            response = std::move(result.packet);
            break;
        }
        std::string err_str = AG_FMT("Upstream failed to perform dns query: {}", result.error.value());
        dbglog_fid(log, request, "{}", err_str);
        if (bool last = (std::distance(i, this->upstreams.end()) == 1); !last) {
            finalize_processed_event(event, request, nullptr, nullptr, upstream.get(), std::move(err_str));
        } else {
            response = ldns_pkt_ptr(create_servfail_response(request));
            log_packet(log, response.get(), "Server failure response");
            std::vector<uint8_t> raw_response = transform_response_to_raw_data(response.get());
            finalize_processed_event(event, request, response.get(), nullptr, upstream.get(), std::move(err_str));
            return raw_response;
        }
    }

    log_packet(log, response.get(), "Upstream dns response");
    const auto ancount = ldns_pkt_ancount(response.get());
    const auto rcode = ldns_pkt_get_rcode(response.get());

    if (LDNS_RCODE_NOERROR == rcode) {
        // CNAME response blocking
        for (size_t i = 0; i < ancount; ++i) {
            auto rr = ldns_rr_list_rr(ldns_pkt_answer(response.get()), i);
            if (!rr || ldns_rr_get_type(rr) != LDNS_RR_TYPE_CNAME) {
                continue;
            }
            auto rdf = ldns_rr_rdf(rr, 0);
            if (!rdf) {
                continue;
            }

            allocated_ptr<char> cname_ptr(ldns_rdf2str(rdf));
            std::string_view cname = cname_ptr.get();
            if (ldns_dname_str_absolute(cname_ptr.get())) {
                cname.remove_suffix(1); // drop trailing dot
            }
            tracelog_fid(log, response.get(), "Response CNAME: {}", cname);

            if (auto raw_blocking_response = apply_filter(cname, request, response.get(), event)) {
                return *raw_blocking_response;
            }
        }

        // DNS64 synthesis
        if (settings->dns64.has_value() && LDNS_RR_TYPE_AAAA == type && 0 == ancount) {
            if (auto synth_response = try_dns64_aaaa_synthesis(successful_upstream, req_holder, response)) {
                response = std::move(synth_response);
                log_packet(log, response.get(), "DNS64 synthesized response");
            }
        }
    }

    std::vector<uint8_t> raw_response = transform_response_to_raw_data(response.get());
    event.bytes_sent = message.size();
    event.bytes_received = raw_response.size();
    finalize_processed_event(event, request, response.get(), nullptr, successful_upstream, std::nullopt);
    put_response_to_cache(std::move(cache_key), std::move(response));
    return raw_response;
}

std::optional<uint8_vector> dns_forwarder::apply_filter(std::string_view hostname, const ldns_pkt *request,
                                                        const ldns_pkt *original_response,
                                                        dns_request_processed_event &event) {
    auto rules = this->filter.match(this->filter_handle, hostname);
    for (const dnsfilter::rule &rule : rules) {
        tracelog_fid(log, request, "Matched rule: {}", rule.text);
    }

    auto effective_rules = dnsfilter::get_effective_rules(rules);
    if (!effective_rules.empty() && !effective_rules[0]->props.test(dnsfilter::RP_EXCEPTION)) {
        set_event_rules(event, effective_rules);
        dbglog_fid(log, request, "DNS query blocked by rule: {}", effective_rules[0]->text);
        ldns_pkt_ptr response(create_blocking_response(request, this->settings, effective_rules));
        log_packet(log, response.get(), "Rule blocked response");
        std::vector<uint8_t> raw_response = transform_response_to_raw_data(response.get());
        finalize_processed_event(event, request, response.get(), original_response, nullptr, std::nullopt);
        return raw_response;
    }

    return std::nullopt;
}
