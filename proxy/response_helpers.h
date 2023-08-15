#pragma once

#include <ldns/ldns.h>

#include "dns/proxy/dnsproxy_settings.h"
#include "svcb.h"

namespace ag::dns {

/**
 * Class with helpers for creating responses.
 */
class ResponseHelpers {
public:
    using ldns_rdf_ptr = UniquePtr<ldns_rdf, &ldns_rdf_deep_free>;
    static constexpr uint32_t SOA_RETRY_DEFAULT = 900;

    static ldns_pkt *create_soa_response(
            const ldns_pkt *request, const DnsProxySettings *settings, uint32_t retry_secs) {
        ldns_pkt *response = create_response_by_request(request);
        ldns_pkt_set_rcode(response, LDNS_RCODE_NOERROR);
        ldns_pkt_push_rr(response, LDNS_SECTION_AUTHORITY, create_soa(request, settings, retry_secs));
        return response;
    }

    static ldns_pkt *create_nxdomain_response(const ldns_pkt *request, const DnsProxySettings *settings) {
        ldns_pkt *response = create_response_by_request(request);
        ldns_pkt_set_rcode(response, LDNS_RCODE_NXDOMAIN);
        ldns_pkt_push_rr(response, LDNS_SECTION_AUTHORITY, create_soa(request, settings, SOA_RETRY_DEFAULT));
        return response;
    }

    static ldns_pkt *create_refused_response(const ldns_pkt *request, const DnsProxySettings *) {
        ldns_pkt *response = create_response_by_request(request);
        ldns_pkt_set_rcode(response, LDNS_RCODE_REFUSED);
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

    /**
     * Create response with IPs from a set of non-blocking DNS hosts rules
     * Logic is following:
     * 1. Set of DNS rules contains set of IPv4 and IPv6 addresses.
     * 2. IPv4 addresses from this list will be returned in response to A request.
     *    And IPv6 addresses from this list will be returned in response to AAAA request.
     * 3. If there are IPv4 addresses in rule set and no IPv6, AAAA request will be responded with NOERROR SOA.
     *    If there are IPv6 addresses in rule set and no IPv4, A request will be responded with NOERROR SOA.
     */
    static ldns_pkt *create_response_with_ips(const ldns_pkt *request, const DnsProxySettings *settings,
            const std::vector<const DnsFilter::Rule *> &rules) {
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
            if (!ipv4_rules.empty()) {
                return create_arecord_response(request, settings, ipv4_rules);
            }
        } else if (type == LDNS_RR_TYPE_AAAA) {
            std::vector<const DnsFilter::Rule *> ipv6_rules;
            ipv6_rules.reserve(rules.size() + 1);
            for (const DnsFilter::Rule *r : rules) {
                const auto *content = std::get_if<DnsFilter::HostsRuleInfo>(&r->content);
                if (content != nullptr && !utils::is_valid_ip4(content->ip)) {
                    ipv6_rules.push_back(r);
                }
            }
            if (!ipv6_rules.empty()) {
                return create_aaaarecord_response(request, settings, ipv6_rules);
            }
        }
        // empty response
        return create_soa_response(request, settings, SOA_RETRY_DEFAULT);
    }

    /**
     * Create response for request that matched some rules.
     * If rule is Adblock-style or Hosts-rule with "blocking IP", then blocking mode is applied.
     * Otherwise, `create_response_with_ips()` is called.
     */
    static ldns_pkt *create_blocking_response(const ldns_pkt *request, const  ldns_pkt *original_response,
            const DnsProxySettings *settings, const std::vector<const DnsFilter::Rule *> &rules,
            std::optional<DnsFilter::ApplyDnsrewriteResult::RewriteInfo> rewritten_info) {
        const ldns_rr *question = ldns_rr_list_rr(ldns_pkt_question(request), 0);

        if (rewritten_info.has_value()) {
            ldns_pkt *result = create_response_by_request(request);
            ldns_pkt_set_rcode(result, rewritten_info->rcode);
            for (auto &rr : rewritten_info->rrs) {
                // If this is a CNAME rewrite, then we shouldn't replace the owner
                // of non-CNAME records for the rewritten name.
                if (!rewritten_info->cname.has_value() || ldns_rr_get_type(rr.get()) == LDNS_RR_TYPE_CNAME) {
                    ldns_rdf_deep_free(ldns_rr_owner(rr.get()));
                    ldns_rr_set_owner(rr.get(), ldns_rdf_clone(ldns_rr_owner(question)));
                }
                ldns_rr_set_ttl(rr.get(), settings->blocked_response_ttl_secs);
                ldns_pkt_push_rr(result, LDNS_SECTION_ANSWER, rr.release());
            }
            return result;
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
        ldns_pkt *result;
        switch (mode) {
        case DnsProxyBlockingMode::REFUSED:
            result = create_refused_response(request, settings);
            break;
        case DnsProxyBlockingMode::NXDOMAIN:
            result = create_nxdomain_response(request, settings);
            break;
        case DnsProxyBlockingMode::ADDRESS:
            result = create_address_or_soa_response(request, original_response, settings);
            break;
        }
        return result;
    }

private:
    /**
     * Create response template from request:
     * 1) Sanitize: leave tx id and question section, clear others
     * 2) Set answer flag
     */
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

    static ldns_rdf *make_mbox(const ldns_pkt *request) {
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
        ldns_rr_push_rdf(soa, ldns_dname_new_frm_str("fake-for-negative-caching.adguard.com."));  // MNAME
        ldns_rr_push_rdf(soa, make_mbox(request));                                                // RNAME
        ldns_rr_push_rdf(soa, ldns_native2rdf_int32(LDNS_RDF_TYPE_TIME, time(nullptr) + 100500)); // SERIAL
        ldns_rr_push_rdf(soa, ldns_native2rdf_int32(LDNS_RDF_TYPE_PERIOD, 1800));                 // REFRESH
        ldns_rr_push_rdf(soa, ldns_native2rdf_int32(LDNS_RDF_TYPE_PERIOD, retry_secs));           // RETRY
        ldns_rr_push_rdf(soa, ldns_native2rdf_int32(LDNS_RDF_TYPE_PERIOD, 604800));               // EXPIRE
        ldns_rr_push_rdf(soa, ldns_native2rdf_int32(LDNS_RDF_TYPE_PERIOD, 86400));                // MINIMUM
        return soa;
    }

    static ldns_pkt *create_arecord_response(const ldns_pkt *request, const DnsProxySettings *settings,
            const std::vector<const DnsFilter::Rule *> &rules) {
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

    static ldns_pkt *create_aaaarecord_response(const ldns_pkt *request, const DnsProxySettings *settings,
            const std::vector<const DnsFilter::Rule *> &rules) {
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

    // Whether the given IP is considered "blocking"
    static bool is_blocking_ip(std::string_view ip) {
        constexpr std::string_view BLOCKING_IPS[] = {"0.0.0.0", "127.0.0.1", "::", "::1", "[::]", "[::1]"};
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

    // Return empty SOA response if question type is not A, AAAA or HTTPS
    static ldns_pkt *create_address_or_soa_response(
            const ldns_pkt *request, const ldns_pkt *original_response, const DnsProxySettings *settings) {
        ldns_rr *question = ldns_rr_list_rr(ldns_pkt_question(request), 0);
        ldns_rr_type type = ldns_rr_get_type(question);

        ldns_rdf_ptr rdf;
        switch (type) {
        case LDNS_RR_TYPE_A: {
            if (!settings->custom_blocking_ipv4.empty()) {
                assert(utils::is_valid_ip4(settings->custom_blocking_ipv4));
                rdf.reset(ldns_rdf_new_frm_str(LDNS_RDF_TYPE_A, settings->custom_blocking_ipv4.c_str()));
            } else if (settings->custom_blocking_ipv6.empty() || is_blocking_ip(settings->custom_blocking_ipv6)) {
                rdf.reset(ldns_rdf_new_frm_str(LDNS_RDF_TYPE_A, "0.0.0.0"));
            } else {
                return create_soa_response(request, settings, SOA_RETRY_DEFAULT);
            }
            break;
        }
        case LDNS_RR_TYPE_AAAA: {
            if (!settings->custom_blocking_ipv6.empty()) {
                assert(utils::is_valid_ip6(settings->custom_blocking_ipv6));
                rdf.reset(ldns_rdf_new_frm_str(LDNS_RDF_TYPE_AAAA, settings->custom_blocking_ipv6.c_str()));
            } else if (settings->custom_blocking_ipv4.empty() || is_blocking_ip(settings->custom_blocking_ipv6)) {
                rdf.reset(ldns_rdf_new_frm_str(LDNS_RDF_TYPE_AAAA, "::"));
            } else {
                return create_soa_response(request, settings, SOA_RETRY_DEFAULT);
            }
            break;
        }
        case LDNS_RR_TYPE_HTTPS: {
            if (!settings->custom_blocking_ipv4.empty() || !settings->custom_blocking_ipv6.empty()) {
                return SvcbHttpsHelpers::modify_response(ldns_pkt_clone(original_response), settings);
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
        ldns_rr_push_rdf(rr, rdf.release());

        ldns_pkt *response = create_response_by_request(request);
        ldns_pkt_push_rr(response, LDNS_SECTION_ANSWER, rr);
        return response;
    }

}; // class ResponseHelpers

} // namespace ag::dns
