#include <thread>

#include "common/cache.h"
#include "common/utils.h"
#include "dns/net/application_verifier.h"
#include "dns/net/default_verifier.h"
#include <cassert>
#include <cstring>
#include <string>

#include "dns/proxy/dnsproxy.h"
#include <ldns/ldns.h>

#include "dns64.h"
#include "dns_forwarder.h"
#include "dns_truncate.h"
#include "retransmission_detector.h"

#define errlog_id(l_, pkt_, fmt_, ...) errlog((l_), "[{}] " fmt_, ldns_pkt_id(pkt_), ##__VA_ARGS__)
#define errlog_fid(l_, pkt_, fmt_, ...) errlog((l_), "[{}] {} " fmt_, ldns_pkt_id(pkt_), __func__, ##__VA_ARGS__)
#define warnlog_id(l_, pkt_, fmt_, ...) warnlog((l_), "[{}] " fmt_, ldns_pkt_id(pkt_), ##__VA_ARGS__)
#define warnlog_fid(l_, pkt_, fmt_, ...) warnlog((l_), "[{}] {} " fmt_, ldns_pkt_id(pkt_), __func__, ##__VA_ARGS__)
#define dbglog_f(l_, fmt_, ...) dbglog((l_), "{} " fmt_, __func__, ##__VA_ARGS__)
#define dbglog_id(l_, pkt_, fmt_, ...) dbglog((l_), "[{}] " fmt_, ldns_pkt_id(pkt_), ##__VA_ARGS__)
#define dbglog_fid(l_, pkt_, fmt_, ...) dbglog((l_), "[{}] {} " fmt_, ldns_pkt_id(pkt_), __func__, ##__VA_ARGS__)
#define tracelog_id(l_, pkt_, fmt_, ...) tracelog((l_), "[{}] " fmt_, ldns_pkt_id(pkt_), ##__VA_ARGS__)
#define tracelog_fid(l_, pkt_, fmt_, ...) tracelog((l_), "[{}] {} " fmt_, ldns_pkt_id(pkt_), __func__, ##__VA_ARGS__)

using std::chrono::duration_cast;

namespace ag::dns {

static constexpr std::string_view MOZILLA_DOH_HOST = "use-application-dns.net.";

static constexpr uint32_t SOA_RETRY_DEFAULT = 900;
static constexpr uint32_t SOA_RETRY_IPV6_BLOCK = 60;

static std::string get_cache_key(const ldns_pkt *request) {
    const auto *question = ldns_rr_list_rr(ldns_pkt_question(request), 0);
    std::string key = fmt::format("{}|{}|{}{}|", // '|' is to avoid collisions
            ldns_rr_get_type(question), ldns_rr_get_class(question), ldns_pkt_edns_do(request) ? "1" : "0",
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

static ldns_pkt *create_response_by_request(const ldns_pkt *request) {
    ldns_pkt *response = nullptr;
    if (ldns_rr *question = ldns_rr_list_rr(ldns_pkt_question(request), 0)) {
        ldns_rr_type type = ldns_rr_get_type(question);
        if (type != LDNS_RR_TYPE_AAAA) {
            type = LDNS_RR_TYPE_A;
        }
        response = ldns_pkt_query_new(
                ldns_rdf_clone(ldns_rr_owner(question)), type, LDNS_RR_CLASS_IN, LDNS_RD | LDNS_RA);
        assert(response != nullptr);
    } else {
        response = ldns_pkt_new();
        assert(response != nullptr);
        ldns_pkt_set_flags(response, LDNS_RD | LDNS_RA);
    }
    ldns_pkt_set_id(response, ldns_pkt_id(request));
    ldns_pkt_set_qr(response, true); // answer flag
    ldns_pkt_set_qdcount(response, ldns_pkt_section_count(request, LDNS_SECTION_QUESTION));
    ldns_rr_list_deep_free(ldns_pkt_question(response));
    ldns_pkt_set_question(response, ldns_pkt_get_section_clone(request, LDNS_SECTION_QUESTION));
    return response;
}

static ldns_rdf *get_mbox(const ldns_pkt *request) {
    using ldns_rdf_ptr = UniquePtr<ldns_rdf, &ldns_rdf_deep_free>;
    const ldns_rr *question = ldns_rr_list_rr(ldns_pkt_question(request), 0);

    ldns_rdf *owner = ldns_rr_owner(question);

    ldns_rdf_ptr hostmaster{ldns_dname_new_frm_str("hostmaster.")};
    ldns_rdf_ptr mbox{ldns_dname_cat_clone(hostmaster.get(), owner)};
    if (mbox) {
        if (auto valid = AllocatedPtr<char>{ldns_rdf2str(mbox.get())}) {
            return mbox.release();
        }
    }

    return hostmaster.release();
}

static uint16_t read_uint16_be(Uint8View pkt) {
    assert(pkt.size() >= 2);
    return pkt[0] << 8 | pkt[1];
}

// Taken from AdGuardHome/dnsforward.go/genSOA
static ldns_rr *create_soa(const ldns_pkt *request, const DnsProxySettings *settings, uint32_t retry_secs) {
    const ldns_rr *question = ldns_rr_list_rr(ldns_pkt_question(request), 0);

    ldns_rr *soa = ldns_rr_new();
    assert(soa != nullptr);
    ldns_rr_set_owner(soa, ldns_rdf_clone(ldns_rr_owner(question)));
    ldns_rr_set_ttl(soa, settings->blocked_response_ttl_secs);
    ldns_rr_set_type(soa, LDNS_RR_TYPE_SOA);
    ldns_rr_set_class(soa, LDNS_RR_CLASS_IN);
    // fill soa rdata
    ldns_rr_push_rdf(soa, ldns_dname_new_frm_str("fake-for-negative-caching.adguard.com.")); // MNAME
    ldns_rr_push_rdf(soa, get_mbox(request)); // RNAME
    ldns_rr_push_rdf(soa, ldns_native2rdf_int32(LDNS_RDF_TYPE_TIME, time(nullptr) + 100500)); // SERIAL
    ldns_rr_push_rdf(soa, ldns_native2rdf_int32(LDNS_RDF_TYPE_PERIOD, 1800)); // REFRESH
    ldns_rr_push_rdf(soa, ldns_native2rdf_int32(LDNS_RDF_TYPE_PERIOD, retry_secs)); // RETRY
    ldns_rr_push_rdf(soa, ldns_native2rdf_int32(LDNS_RDF_TYPE_PERIOD, 604800)); // EXPIRE
    ldns_rr_push_rdf(soa, ldns_native2rdf_int32(LDNS_RDF_TYPE_PERIOD, 86400)); // MINIMUM
    return soa;
}

static ldns_pkt *create_nxdomain_response(const ldns_pkt *request, const DnsProxySettings *settings) {
    ldns_pkt *response = create_response_by_request(request);
    ldns_pkt_set_rcode(response, LDNS_RCODE_NXDOMAIN);
    ldns_pkt_push_rr(response, LDNS_SECTION_AUTHORITY, create_soa(request, settings, 900));
    return response;
}

static ldns_pkt *create_refused_response(const ldns_pkt *request, const DnsProxySettings *) {
    ldns_pkt *response = create_response_by_request(request);
    ldns_pkt_set_rcode(response, LDNS_RCODE_REFUSED);
    return response;
}

static ldns_pkt *create_soa_response(const ldns_pkt *request, const DnsProxySettings *settings, uint32_t retry_secs) {
    ldns_pkt *response = create_response_by_request(request);
    ldns_pkt_set_rcode(response, LDNS_RCODE_NOERROR);
    ldns_pkt_push_rr(response, LDNS_SECTION_AUTHORITY, create_soa(request, settings, retry_secs));
    return response;
}

static ldns_pkt *create_arecord_response(
        const ldns_pkt *request, const DnsProxySettings *settings, const std::vector<const DnsFilter::Rule *> &rules) {
    const ldns_rr *question = ldns_rr_list_rr(ldns_pkt_question(request), 0);

    ldns_rr *answer = ldns_rr_new();
    assert(answer != nullptr);
    ldns_rr_set_owner(answer, ldns_rdf_clone(ldns_rr_owner(question)));
    ldns_rr_set_ttl(answer, settings->blocked_response_ttl_secs);
    ldns_rr_set_type(answer, LDNS_RR_TYPE_A);
    ldns_rr_set_class(answer, LDNS_RR_CLASS_IN);
    for (auto *rule : rules) {
        const std::string &ip = std::get<DnsFilter::HostsRuleInfo>(rule->content).ip;
        ldns_rdf *rdf = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_A, ip.c_str());
        assert(rdf);
        ldns_rr_push_rdf(answer, rdf);
    }

    ldns_pkt *response = create_response_by_request(request);
    ldns_pkt_push_rr(response, LDNS_SECTION_ANSWER, answer);
    return response;
}

static ldns_pkt *create_aaaarecord_response(
        const ldns_pkt *request, const DnsProxySettings *settings, const std::vector<const DnsFilter::Rule *> &rules) {
    const ldns_rr *question = ldns_rr_list_rr(ldns_pkt_question(request), 0);

    ldns_rr *answer = ldns_rr_new();
    assert(answer != nullptr);
    ldns_rr_set_owner(answer, ldns_rdf_clone(ldns_rr_owner(question)));
    ldns_rr_set_ttl(answer, settings->blocked_response_ttl_secs);
    ldns_rr_set_type(answer, LDNS_RR_TYPE_AAAA);
    ldns_rr_set_class(answer, LDNS_RR_CLASS_IN);
    for (auto *rule : rules) {
        const std::string &ip = std::get<DnsFilter::HostsRuleInfo>(rule->content).ip;
        ldns_rdf *rdf = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_AAAA, ip.c_str());
        assert(rdf);
        ldns_rr_push_rdf(answer, rdf);
    }

    ldns_pkt *response = create_response_by_request(request);
    ldns_pkt_push_rr(response, LDNS_SECTION_ANSWER, answer);
    return response;
}

static ldns_pkt *create_response_with_ips(
        const ldns_pkt *request, const DnsProxySettings *settings, const std::vector<const DnsFilter::Rule *> &rules) {
    const ldns_rr *question = ldns_rr_list_rr(ldns_pkt_question(request), 0);
    ldns_rr_type type = ldns_rr_get_type(question);

    if (type == LDNS_RR_TYPE_A) {
        std::vector<const DnsFilter::Rule *> ipv4_rules;
        ipv4_rules.reserve(rules.size() + 1);
        for (const DnsFilter::Rule *r : rules) {
            const auto *content = std::get_if<DnsFilter::HostsRuleInfo>(&r->content);
            if (content != nullptr && utils::is_valid_ip4(content->ip)) {
                ipv4_rules.push_back(r);
            }
        }
        if (ipv4_rules.size() != 0) {
            return create_arecord_response(request, settings, ipv4_rules);
        }
    } else if (type == LDNS_RR_TYPE_AAAA) {
        std::vector<const DnsFilter::Rule *>ipv6_rules;
        ipv6_rules.reserve(rules.size() + 1);
        for (const DnsFilter::Rule *r : rules) {
            const auto *content = std::get_if<DnsFilter::HostsRuleInfo>(&r->content);
            if (content != nullptr && !utils::is_valid_ip4(content->ip)) {
                ipv6_rules.push_back(r);
            }
        }
        if (ipv6_rules.size() != 0) {
            return create_aaaarecord_response(request, settings, ipv6_rules);
        }
    }
    // empty response
    return create_soa_response(request, settings, SOA_RETRY_DEFAULT);
}

// Whether the given IP is considered "blocking"
static bool is_blocking_ip(std::string_view ip) {
    static constexpr std::string_view BLOCKING_IPS[] = {"0.0.0.0", "127.0.0.1", "::", "::1", "[::]", "[::1]"};
    return !ip.empty()
            && std::any_of(std::begin(BLOCKING_IPS), std::end(BLOCKING_IPS), [ip](std::string_view blocking_ip) {
                   return blocking_ip == ip;
               });
}

// Whether the given set of rules contains IPs considered "blocking",
// i.e. the proxy must respond with a blocking response according to the blocking_mode
static bool rules_contain_blocking_ip(const std::vector<const DnsFilter::Rule *> &rules) {
    return std::any_of(rules.begin(), rules.end(), [](const DnsFilter::Rule *rule) -> bool {
        const auto *content = std::get_if<DnsFilter::HostsRuleInfo>(&rule->content);
        return content != nullptr && is_blocking_ip(content->ip);
    });
}

// Return empty SOA response if question type is not A or AAAA
static ldns_pkt *create_address_or_soa_response(const ldns_pkt *request, const DnsProxySettings *settings) {
    ldns_rr *question = ldns_rr_list_rr(ldns_pkt_question(request), 0);
    ldns_rr_type type = ldns_rr_get_type(question);

    ldns_rdf *rdf;
    switch (type) {
    case LDNS_RR_TYPE_A: {
        if (!settings->custom_blocking_ipv4.empty()) {
            assert(utils::is_valid_ip4(settings->custom_blocking_ipv4));
            rdf = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_A, settings->custom_blocking_ipv4.c_str());
        } else if (settings->custom_blocking_ipv6.empty() || is_blocking_ip(settings->custom_blocking_ipv6)) {
            rdf = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_A, "0.0.0.0");
        } else {
            return create_soa_response(request, settings, SOA_RETRY_DEFAULT);
        }
        break;
    }
    case LDNS_RR_TYPE_AAAA: {
        if (!settings->custom_blocking_ipv6.empty()) {
            assert(utils::is_valid_ip6(settings->custom_blocking_ipv6));
            rdf = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_AAAA, settings->custom_blocking_ipv6.c_str());
        } else if (settings->custom_blocking_ipv4.empty() || is_blocking_ip(settings->custom_blocking_ipv6)) {
            rdf = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_AAAA, "::");
        } else {
            return create_soa_response(request, settings, SOA_RETRY_DEFAULT);
        }
        break;
    }
    default:
        return create_soa_response(request, settings, SOA_RETRY_DEFAULT);
    }

    ldns_rr *rr = ldns_rr_new();
    ldns_rr_set_owner(rr, ldns_rdf_clone(ldns_rr_owner(question)));
    ldns_rr_set_ttl(rr, settings->blocked_response_ttl_secs);
    ldns_rr_set_type(rr, type);
    ldns_rr_set_class(rr, ldns_rr_get_class(question));
    ldns_rr_push_rdf(rr, rdf);

    ldns_pkt *response = create_response_by_request(request);
    ldns_pkt_push_rr(response, LDNS_SECTION_ANSWER, rr);
    return response;
}

static ldns_pkt *create_blocking_response(const ldns_pkt *request, const DnsProxySettings *settings,
        const std::vector<const DnsFilter::Rule *> &rules,
        std::optional<DnsFilter::ApplyDnsrewriteResult::RewriteInfo> rewritten_info) {
    const ldns_rr *question = ldns_rr_list_rr(ldns_pkt_question(request), 0);
    ldns_rr_type type = ldns_rr_get_type(question);

    if (rewritten_info.has_value()) {
        ldns_pkt *response = create_response_by_request(request);
        ldns_pkt_set_rcode(response, rewritten_info->rcode);
        for (auto &rr : rewritten_info->rrs) {
            ldns_rr_set_owner(rr.get(), ldns_rdf_clone(ldns_rr_owner(question)));
            ldns_rr_set_ttl(rr.get(), settings->blocked_response_ttl_secs);
            ldns_pkt_push_rr(response, LDNS_SECTION_ANSWER, rr.release());
        }
        return response;
    }
    DnsProxyBlockingMode mode;
    const DnsFilter::Rule *effective_rule = rules.front();
    if (nullptr != std::get_if<DnsFilter::AdblockRuleInfo>(&effective_rule->content)) {
        mode = settings->adblock_rules_blocking_mode;
    } else if (rules_contain_blocking_ip(rules)) {
        mode = settings->hosts_rules_blocking_mode;
    } else { // hosts-style IP rule
        return create_response_with_ips(request, settings, rules);
    }
    ldns_pkt *response;
    switch (mode) {
    case DnsProxyBlockingMode::REFUSED:
        response = create_refused_response(request, settings);
        break;
    case DnsProxyBlockingMode::NXDOMAIN:
        response = create_nxdomain_response(request, settings);
        break;
    case DnsProxyBlockingMode::ADDRESS:
        response = create_address_or_soa_response(request, settings);
        break;
    }
    return response;
}

static ldns_pkt *create_servfail_response(const ldns_pkt *request) {
    ldns_pkt *response = create_response_by_request(request);
    ldns_pkt_set_rcode(response, LDNS_RCODE_SERVFAIL);
    return response;
}

static ldns_pkt *create_formerr_response(uint16_t id) {
    ldns_pkt *response = ldns_pkt_new();
    ldns_pkt_set_id(response, id);
    ldns_pkt_set_rcode(response, LDNS_RCODE_FORMERR);
    return response;
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

std::string DnsForwarderUtils::rr_list_to_string(const ldns_rr_list *rr_list) {
    if (rr_list == nullptr) {
        return {};
    }
    AllocatedPtr<char> answer(ldns_rr_list2str(rr_list));
    if (answer == nullptr) {
        return {};
    }
    std::string_view answer_view = answer.get();
    std::string out;
    out.reserve(answer_view.size());
    for (auto record : ag::utils::split_by(answer_view, '\n')) {
        auto record_parts = ag::utils::split_by(record, '\t');
        auto it = record_parts.begin();
        if (record_parts.size() >= 4) {
            it++; // Skip owner
            it++; // Skip ttl
            it++; // Skip class
            out += *it++; // Add type
            out += ',';
            // Add serialized RDFs
            while (it != record_parts.end()) {
                out += ' ';
                out += *it++;
            }
            out += '\n';
        }
    }
    return out;
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
    std::scoped_lock l(m_dns64_prefixes->mtx);

    if (m_dns64_prefixes->val.empty()) {
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
                "DNS64: could not synthesize AAAA response: upstream failed to perform A query:\n{}", response_a.error()->str());
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

        for (const Uint8Vector &pref : m_dns64_prefixes->val) { // assume `dns64_prefixes->mtx` is held
            const auto synth_res =
                    dns64::synthesize_ipv4_embedded_ipv6_address({pref.data(), std::size(pref)}, ip4);
            if (synth_res.has_error()) {
                dbglog_fid(
                        m_log, request.get(), "DNS64: could not synthesize IPv4-embedded IPv6:\n{}", synth_res.error()->str());
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

static coro::Task<void>
discover_dns64_prefixes(std::vector<UpstreamOptions> uss, std::shared_ptr<SocketFactory> socket_factory,
                        dns64::Prefixes prefixes, Logger logger, EventLoop &loop, uint32_t max_tries,
                        Millis wait_time);

std::pair<bool, ErrString> DnsForwarder::init(EventLoopPtr loop, const DnsProxySettings &settings, const DnsProxyEvents &events) {
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
        if (SocketAddress addr(settings.outbound_proxy->address, settings.outbound_proxy->port); !addr.valid()) {
            auto err = AG_FMT("Invalid outbound proxy address: {}:{}", settings.outbound_proxy->address,
                    settings.outbound_proxy->port);
            errlog(m_log, "{}", err);
            this->deinit();
            return {false, std::move(err)};
        }
        sf_parameters.oproxy_settings = &m_settings->outbound_proxy.value();
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

    m_dns64_prefixes = std::make_shared<WithMtx<std::vector<Uint8Vector>>>();
    if (settings.dns64.has_value()) {
        infolog(m_log, "DNS64 discovery is enabled");
        coro::run_detached(discover_dns64_prefixes(settings.dns64->upstreams, m_socket_factory, m_dns64_prefixes,
                m_log, *m_loop, settings.dns64->max_tries, settings.dns64->wait_time));
    }

    {
        std::scoped_lock l(m_response_cache.mtx);
        m_response_cache.val.set_capacity(m_settings->dns_cache_size);
    }

    infolog(m_log, "Forwarder initialized");
    return {true, std::move(err_or_warn)};
}

static coro::Task<void> discover_dns64_prefixes(std::vector<UpstreamOptions> uss,
        std::shared_ptr<SocketFactory> socket_factory, dns64::Prefixes prefixes,
        Logger logger, EventLoop &loop, uint32_t max_tries, Millis wait_time) {

    UpstreamFactory us_factory({.loop = loop, .socket_factory = socket_factory.get()});
    auto i = max_tries;
    while (i--) {
        co_await loop.co_sleep(wait_time);
        for (auto &us: uss) {
            auto upstream_result = us_factory.create_upstream(us);
            if (upstream_result.has_error()) {
                dbglog(logger, "DNS64: failed to create DNS64 upstream: {}", upstream_result.error()->str());
                continue;
            }

            auto result = co_await dns64::discover_prefixes(upstream_result.value());
            if (result.has_error()) {
                dbglog(logger, "DNS64: error discovering prefixes:\n{}", result.error()->str());
                continue;
            }

            if (result->empty()) {
                dbglog(logger, "DNS64: no prefixes discovered, retrying");
                continue;
            }

            std::scoped_lock l(prefixes->mtx);
            prefixes->val = std::move(result.value());

            infolog(logger, "DNS64 prefixes discovered: {}", prefixes->val.size());
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

    infolog(m_log, "Destroying DNS filter...");
    m_filter.destroy(std::exchange(m_filter_handle, nullptr));
    infolog(m_log, "Done");

    infolog(m_log, "Destroying fallback filter...");
    m_filter.destroy(std::exchange(m_fallback_filter_handle, nullptr));
    infolog(m_log, "Done");

    {
        infolog(m_log, "Clearing cache...");
        std::scoped_lock l(m_response_cache.mtx);
        m_response_cache.val.clear();
        infolog(m_log, "Done");
    }

    infolog(m_log, "Deinitialized");
}

static bool has_unsupported_extensions(const ldns_pkt *pkt) {
    return ldns_pkt_edns_data(pkt) || ldns_pkt_edns_extended_rcode(pkt) || ldns_pkt_edns_unassigned(pkt);
}

// Returns null result if no cache entry satisfies the given key.
// Otherwise, a response is synthesized from the cached template.
// If the cache entry is expired, it becomes least recently used,
// all response records' TTLs are set to 1 second,
// and `expired` is set to `true`.
CacheResult DnsForwarder::create_response_from_cache(const std::string &key, const ldns_pkt *request) {
    CacheResult r{};

    if (!m_settings->dns_cache_size) { // Caching disabled
        return r;
    }

    if (has_unsupported_extensions(request)) {
        dbglog(m_log, "{}: Request has unsupported extensions", __func__);
        return r;
    }

    uint32_t ttl;
    {
        std::shared_lock l(m_response_cache.mtx);
        auto &cache = m_response_cache.val;

        auto cached_response_acc = cache.get(key);
        if (!cached_response_acc) {
            dbglog(m_log, "{}: Cache miss for key {}", __func__, key);
            return {nullptr};
        }

        r.upstream_id = cached_response_acc->upstream_id;
        auto cached_response_ttl = std::chrono::ceil<Secs>(cached_response_acc->expires_at - ag::SteadyClock::now());
        if (cached_response_ttl.count() <= 0) {
            cache.make_lru(cached_response_acc);
            dbglog(m_log, "{}: Expired cache entry for key {}", __func__, key);
            ttl = 1;
            r.expired = true;
        } else {
            ttl = cached_response_ttl.count();
        }

        r.response.reset(ldns_pkt_clone(cached_response_acc->response.get()));
    }

    // Patch response id
    ldns_pkt_set_id(r.response.get(), ldns_pkt_id(request));

    // Patch EDNS UDP SIZE
    if (ldns_pkt_edns(r.response.get())) {
        ldns_pkt_set_edns_udp_size(r.response.get(), UDP_RECV_BUF_SIZE);
    }

    // Patch response question section
    assert(!ldns_pkt_question(r.response.get()));
    ldns_pkt_set_qdcount(r.response.get(), ldns_pkt_qdcount(request));
    ldns_pkt_set_question(r.response.get(), ldns_pkt_get_section_clone(request, LDNS_SECTION_QUESTION));

    // Patch response TTLs
    for (int_fast32_t i = 0; i < ldns_pkt_ancount(r.response.get()); ++i) {
        ldns_rr_set_ttl(ldns_rr_list_rr(ldns_pkt_answer(r.response.get()), i), ttl);
    }
    for (int_fast32_t i = 0; i < ldns_pkt_nscount(r.response.get()); ++i) {
        ldns_rr_set_ttl(ldns_rr_list_rr(ldns_pkt_authority(r.response.get()), i), ttl);
    }
    for (int_fast32_t i = 0; i < ldns_pkt_arcount(r.response.get()); ++i) {
        ldns_rr_set_ttl(ldns_rr_list_rr(ldns_pkt_additional(r.response.get()), i), ttl);
    }

    return r;
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
void DnsForwarder::put_response_into_cache(std::string key, ldns_pkt_ptr response, std::optional<int32_t> upstream_id) {
    if (!m_settings->dns_cache_size) {
        // Caching disabled
        return;
    }
    if (ldns_pkt_tc(response.get()) // Truncated
            || ldns_pkt_qdcount(response.get()) != 1 // Invalid
            || ldns_pkt_get_rcode(response.get()) != LDNS_RCODE_NOERROR // Error
            || has_unsupported_extensions(response.get())) {
        // Not cacheable
        return;
    }

    const auto *question = ldns_rr_list_rr(ldns_pkt_question(response.get()), 0);
    const auto type = ldns_rr_get_type(question);
    if (type == LDNS_RR_TYPE_A || type == LDNS_RR_TYPE_AAAA) {
        // Check contains at least one record of requested type
        bool found = false;
        for (int_fast32_t i = 0; i < ldns_pkt_ancount(response.get()); ++i) {
            const ldns_rr *rr = ldns_rr_list_rr(ldns_pkt_answer(response.get()), i);
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

    CachedResponse cached_response{
            .response = std::move(response),
            .expires_at = SteadyClock::now() + Secs(min_rr_ttl),
            .upstream_id = upstream_id,
    };

    std::unique_lock l(m_response_cache.mtx);
    auto &cache = m_response_cache.val;
    cache.insert(std::move(key), std::move(cached_response));
}

static ldns_rr_type question_rr_type(const ldns_pkt *request) {
    return ldns_rr_get_type(ldns_rr_list_rr(ldns_pkt_question(request), 0));
}

coro::Task<Uint8Vector> DnsForwarder::handle_message_internal(
        Uint8View message, const DnsMessageInfo *info, bool fallback_only, uint16_t pkt_id) {
    DnsRequestProcessedEvent event = {};
    event.start_time = duration_cast<Millis>(SystemClock::now().time_since_epoch()).count();

    ldns_pkt *request;
    ldns_status status = ldns_wire2pkt(&request, message.data(), message.length());
    if (status != LDNS_STATUS_OK) {
        std::string err = AG_FMT("Failed to parse payload: {} ({})", ldns_get_errorstr_by_id(status), status);
        dbglog(m_log, "{} {}", __func__, err);
        finalize_processed_event(event, nullptr, nullptr, nullptr, std::nullopt, std::move(err));
        ldns_pkt_ptr response(create_formerr_response(pkt_id));
        log_packet(m_log, response.get(), "Format error response");
        co_return transform_response_to_raw_data(response.get());
    }

    ldns_pkt_ptr req_holder = ldns_pkt_ptr(request);
    log_packet(m_log, request, "Client request", info);

    const ldns_rr *question = ldns_rr_list_rr(ldns_pkt_question(request), 0);
    if (question == nullptr) {
        std::string err = "Message has no question section";
        dbglog_fid(m_log, request, "{}", err);
        ldns_pkt_ptr response(create_servfail_response(request));
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

    std::string cache_key = get_cache_key(request);
    CacheResult cached = create_response_from_cache(cache_key, request);

    if (cached.response && (!cached.expired || m_settings->optimistic_cache)) {
        log_packet(m_log, cached.response.get(), "Cached response");
        event.cache_hit = true;
        truncate_response(cached.response.get(), request, info);
        finalize_processed_event(event, request, cached.response.get(), nullptr, cached.upstream_id, std::nullopt);
        Uint8Vector raw_response = transform_response_to_raw_data(cached.response.get());
        if (cached.expired) {
            assert(m_settings->optimistic_cache);
            this->optimistic_cache_background_resolve(
                        std::move(req_holder),
                        std::move(cache_key),
                        std::string{normalized_domain})
                    .run_detached();
        }
        co_return raw_response;
    }

    const ldns_rr_type type = ldns_rr_get_type(question);

    // disable Mozilla DoH
    if ((type == LDNS_RR_TYPE_A || type == LDNS_RR_TYPE_AAAA) && 0 == strcmp(domain.get(), MOZILLA_DOH_HOST.data())) {
        ldns_pkt_ptr response(create_nxdomain_response(request, m_settings));
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
            ldns_pkt_ptr response(create_soa_response(request, m_settings, SOA_RETRY_IPV6_BLOCK));
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

    bool is_our_do_bit = do_dnssec_log_logic(request);

    // If this is a retransmitted request, use fallback upstreams only
    auto [response, selected_upstream] = co_await do_upstream_exchange(
            normalized_domain, request, fallback_only, info);

    if (!response) {
        auto err = response.error();
        response = ldns_pkt_ptr(create_servfail_response(request));
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
            remove_ech_svcparam(response->get());
        }
    }

    truncate_response(response->get(), request, info);
    Uint8Vector raw_response = transform_response_to_raw_data(response->get());
    event.bytes_sent = message.size();
    event.bytes_received = raw_response.size();
    finalize_processed_event(event, request, response->get(), nullptr, selected_upstream->options().id, std::nullopt);
    put_response_into_cache(std::move(cache_key), std::move(response.value()), selected_upstream->options().id);
    co_return raw_response;
}

coro::Task<std::optional<Uint8Vector>> DnsForwarder::apply_cname_filter(
        const ldns_rr *cname_rr, const ldns_pkt *request,
        const ldns_pkt *response, DnsRequestProcessedEvent &event, std::vector<DnsFilter::Rule> &last_effective_rules,
        bool fallback_only) {

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

coro::Task<std::optional<Uint8Vector>> DnsForwarder::apply_ip_filter(
        const ldns_rr *rr, const ldns_pkt *request,
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

    co_return co_await apply_filter(
            {.domain = addr_str, .rr_type = ldns_rr_get_type(rr)}, request, response, event,
            last_effective_rules, fallback_only);
}

coro::Task<std::optional<Uint8Vector>> DnsForwarder::apply_filter(
        DnsFilter::MatchParam match, const ldns_pkt *request,
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

    ldns_pkt_ptr response(
            create_blocking_response(request, m_settings, effective_rules.leftovers, std::move(rewrite_info)));
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

coro::Task<UpstreamExchangeResult> DnsForwarder::do_upstream_exchange(
        std::string_view normalized_domain, ldns_pkt *request, bool fallback_only, const DnsMessageInfo *info) {
    bool use_only_fallbacks
            = !m_fallbacks.empty() && (fallback_only || apply_fallback_filter(normalized_domain, request));
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
                if (!retry_result.has_error()) {
                    co_return {std::move(retry_result.value()), cur_upstream};
                }
                err = make_error(DE_NESTED_DNS_ERROR, AG_FMT("Upstream ({}) exchange failed: first reason is:\n{}\nsecond reason is:", address, result.error()->str()), retry_result.error());
                dbglog_id(m_log, request, "{}", err->str());
            } else {
                err = make_error(DE_NESTED_DNS_ERROR, AG_FMT("Upstream ({}) exchange failed", address, result.error()->str()));
                dbglog_id(m_log, request, "{}", err->str());
            }
        }
    }
    co_return {err, cur_upstream};
}

coro::Task<void> DnsForwarder::optimistic_cache_background_resolve(ldns_pkt_ptr req,
        std::string key, std::string normalized_domain) {
    dbglog_id(m_log, req.get(), "Starting async upstream exchange for {}", key);
    std::weak_ptr<bool> guard = m_shutdown_guard;
    auto [res, upstream] = co_await do_upstream_exchange(normalized_domain, req.get(), false);
    if (guard.expired()) {
        co_return;
    }
    if (res.has_error()) {
        dbglog_id(m_log, req.get(), "Async upstream exchange failed, removing entry from cache: {}", res.error()->str());
        m_response_cache.val.erase(key);
    } else {
        log_packet(m_log, res->get(), "Async upstream exchange result");
        this->put_response_into_cache(key, std::move(res.value()), upstream->options().id);
    }
    co_return;
}

bool DnsForwarder::do_dnssec_log_logic(ldns_pkt *request) {
    bool is_our_do_bit = false;
    bool request_has_do_bit = ldns_pkt_edns_do(request);

    // if request has DO bit then we don't change it
    if (m_settings->enable_dnssec_ok && !request_has_do_bit) {
        // https://tools.ietf.org/html/rfc3225#section-3
        ldns_pkt_set_edns_do(request, true);
        // @todo truncate reply to size expected by client
        ldns_pkt_set_edns_udp_size(request, UDP_RECV_BUF_SIZE);
        is_our_do_bit = true;
    }

    return is_our_do_bit;
}

static ldns_rr_list *get_pkt_section(ldns_pkt *pkt, ldns_pkt_section section) {
    switch (section) {
    case LDNS_SECTION_QUESTION:
        return ldns_pkt_question(pkt);
    case LDNS_SECTION_ANSWER:
        return ldns_pkt_answer(pkt);
    case LDNS_SECTION_AUTHORITY:
        return ldns_pkt_authority(pkt);
    case LDNS_SECTION_ADDITIONAL:
        return ldns_pkt_additional(pkt);
    case LDNS_SECTION_ANY:
    case LDNS_SECTION_ANY_NOQUESTION:
        assert(0);
        break;
    }
    return nullptr;
}

static void set_pkt_section(ldns_pkt *pkt, ldns_pkt_section section, ldns_rr_list *new_value) {
    switch (section) {
    case LDNS_SECTION_QUESTION:
        return ldns_pkt_set_question(pkt, new_value);
    case LDNS_SECTION_ANSWER:
        return ldns_pkt_set_answer(pkt, new_value);
    case LDNS_SECTION_AUTHORITY:
        return ldns_pkt_set_authority(pkt, new_value);
    case LDNS_SECTION_ADDITIONAL:
        return ldns_pkt_set_additional(pkt, new_value);
    case LDNS_SECTION_ANY:
    case LDNS_SECTION_ANY_NOQUESTION:
        assert(0);
    }
}

// Scrub all DNSSEC RRs from the answer and authority sections,
// except those which are requested
// Return true if pkt was modified
static bool scrub_dnssec_rrs(ldns_pkt *pkt) {
    static constexpr ldns_rr_type DNSSEC_RRTYPES[]
            = {LDNS_RR_TYPE_DS, LDNS_RR_TYPE_DNSKEY, LDNS_RR_TYPE_NSEC, LDNS_RR_TYPE_NSEC3, LDNS_RR_TYPE_RRSIG};

    ldns_rr_type qtype = ldns_rr_get_type(ldns_rr_list_rr(ldns_pkt_question(pkt), 0));
    bool modified = false;

    for (ldns_pkt_section section : {LDNS_SECTION_ANSWER, LDNS_SECTION_AUTHORITY}) {
        size_t old_count = ldns_pkt_section_count(pkt, section);
        if (old_count == 0) {
            continue;
        }
        auto *old_section = get_pkt_section(pkt, section);
        auto *new_section = ldns_rr_list_new();
        for (size_t i = 0; i < old_count; ++i) {
            auto *rr = ldns_rr_list_rr(old_section, i);
            ldns_rr_type type = ldns_rr_get_type(rr);
            if ((section == LDNS_SECTION_ANSWER && type == qtype)
                    || std::none_of(
                            std::begin(DNSSEC_RRTYPES), std::end(DNSSEC_RRTYPES), [type](ldns_enum_rr_type extype) {
                                return extype == type;
                            })) {
                ldns_rr_list_push_rr(new_section, ldns_rr_clone(rr));
            }
        }
        modified = modified || ldns_rr_list_rr_count(new_section) != old_count;
        ldns_rr_list_deep_free(old_section);
        set_pkt_section(pkt, section, new_section);
        ldns_pkt_set_section_count(pkt, section, ldns_rr_list_rr_count(new_section));
    }

    return modified;
}

bool DnsForwarder::finalize_dnssec_log_logic(ldns_pkt *response, bool is_our_do_bit) {
    bool server_uses_dnssec = false;

    if (m_settings->enable_dnssec_ok) {
        server_uses_dnssec = ldns_dnssec_pkt_has_rrsigs(response);
        tracelog(m_log, "Server uses DNSSEC: {}", server_uses_dnssec ? "YES" : "NO");
        if (is_our_do_bit && scrub_dnssec_rrs(response)) {
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
        dbglog_f(m_log, "Not responding to malformed message");
        co_return {};
    }

    uint16_t pkt_id = read_uint16_be(message);

    // If there's enough info, register this request
    bool retransmitted = false;
    bool retransmission_handling = m_settings->enable_retransmission_handling && info && info->proto == utils::TP_UDP;
    if (retransmission_handling) {
        if (m_retransmission_detector.register_packet(pkt_id, info->peername) > 1) {
            dbglog_f(m_log, "Detected retransmitted request [{}] from {}", pkt_id, info->peername.str());
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

// Remove the "ech" parameter from the SvcParams part of any SVCB/HTTPS record contained in `response`
void DnsForwarder::remove_ech_svcparam(ldns_pkt *response) {
    for (size_t i = 0; i < ldns_pkt_ancount(response); ++i) {
        ldns_rr *rr = ldns_rr_list_rr(ldns_pkt_answer(response), i);

        if (auto type = ldns_rr_get_type(rr);
                (type != LDNS_RR_TYPE_SVCB && type != LDNS_RR_TYPE_HTTPS) || (ldns_rr_rd_count(rr) != 3)) {
            continue;
        }

        ldns_rdf *params = ldns_rr_rdf(rr, 2);

        if (ldns_rdf_get_type(params) != LDNS_RDF_TYPE_SVCPARAMS) {
            continue;
        }

        uint8_t *current_param_start = nullptr;
        uint16_t key, len;
        ag::Uint8View params_tail = {ldns_rdf_data(params), ldns_rdf_size(params)};
        while (params_tail.size() >= sizeof(key)) {
            current_param_start = (uint8_t *) params_tail.data();

            std::memcpy(&key, params_tail.data(), sizeof(key));
            params_tail.remove_prefix(sizeof(key));

            if (params_tail.size() < sizeof(len)) {
                break;
            }

            std::memcpy(&len, params_tail.data(), sizeof(len));
            params_tail.remove_prefix(sizeof(len));

            key = ntohs(key);
            len = ntohs(len);

            if (params_tail.size() < len) {
                break;
            }

            params_tail.remove_prefix(len);

            if (key == LDNS_SVCPARAM_KEY_ECHCONFIG) {
                dbglog_fid(m_log, response, "Removing ECH parameters from SVCB/HTTPS RR");
                std::memmove(current_param_start, params_tail.data(), params_tail.size());
                ldns_rdf_set_size(params, ldns_rdf_size(params) - sizeof(key) - sizeof(len) - len);
                break;
            }
        }
    }
}

} // namespace ag::dns
