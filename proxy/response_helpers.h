#pragma once

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <optional>
#include <string_view>
#include <variant>
#include <vector>

#include <ldns/ldns.h>

#include "common/defs.h"
#include "common/utils.h"
#include "dns/proxy/dnsproxy_settings.h"

#include "svcb.h"

namespace ag::dns {

/**
 * Class with helpers for creating responses.
 */
class ResponseHelpers {
public:
    using ldns_rdf_ptr = UniquePtr<ldns_rdf, &ldns_rdf_deep_free>; // NOLINT(*-identifier-naming)
    static constexpr uint32_t SOA_RETRY_DEFAULT = 900;
    struct NeedsResponse{};
    using CreateResponseResult = std::variant<ldns_pkt_ptr, NeedsResponse>;

    static CreateResponseResult create_soa_response(
            const ldns_pkt *request, const DnsProxySettings *settings, uint32_t retry_secs) {
        ldns_pkt *response = create_response_by_request(request);
        ldns_pkt_set_rcode(response, LDNS_RCODE_NOERROR);
        ldns_pkt_push_rr(response, LDNS_SECTION_AUTHORITY, create_soa(request, settings, retry_secs));
        return ldns_pkt_ptr{response};
    }

    static CreateResponseResult create_nxdomain_response(const ldns_pkt *request, const DnsProxySettings *settings) {
        ldns_pkt *response = create_response_by_request(request);
        ldns_pkt_set_rcode(response, LDNS_RCODE_NXDOMAIN);
        ldns_pkt_push_rr(response, LDNS_SECTION_AUTHORITY, create_soa(request, settings, SOA_RETRY_DEFAULT));
        return ldns_pkt_ptr{response};
    }

    static CreateResponseResult create_refused_response(const ldns_pkt *request, const DnsProxySettings *) {
        ldns_pkt *response = create_response_by_request(request);
        ldns_pkt_set_rcode(response, LDNS_RCODE_REFUSED);
        return ldns_pkt_ptr{response};
    }

    static CreateResponseResult create_servfail_response(const ldns_pkt *request) {
        ldns_pkt *response = create_response_by_request(request);
        ldns_pkt_set_rcode(response, LDNS_RCODE_SERVFAIL);
        return ldns_pkt_ptr{response};
    }

    static CreateResponseResult create_formerr_response(uint16_t id) {
        ldns_pkt *response = ldns_pkt_new();
        ldns_pkt_set_id(response, id);
        ldns_pkt_set_rcode(response, LDNS_RCODE_FORMERR);
        return ldns_pkt_ptr{response};
    }

    static std::vector<const char *> extract_ips(const std::vector<const DnsFilter::Rule *> &rules) {
        std::vector<const char *> ret;
        for (const auto &r : rules) {
            const auto *content = std::get_if<DnsFilter::HostsRuleInfo>(&r->content);
            if (content) {
                ret.push_back(content->ip.c_str());
            }
        }
        return ret;
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
    static CreateResponseResult create_response_with_ips(const ldns_pkt *request, const ldns_pkt *original_response, const DnsProxySettings *settings,
            const std::vector<const char *> &ips) {
        const ldns_rr *question = ldns_rr_list_rr(ldns_pkt_question(request), 0);
        ldns_rr_type type = ldns_rr_get_type(question);

        if (type == LDNS_RR_TYPE_A) {
            std::vector<const char *> ipv4s;
            ipv4s.reserve(ips.size() + 1);
            std::copy_if(ips.begin(), ips.end(), std::back_inserter(ipv4s), &utils::is_valid_ip4);
            if (!ipv4s.empty()) {
                return create_arecord_response(request, settings, ipv4s);
            }
        } else if (type == LDNS_RR_TYPE_AAAA) {
            std::vector<const char *> ipv6s;
            ipv6s.reserve(ips.size() + 1);
            std::copy_if(ips.begin(), ips.end(), std::back_inserter(ipv6s), &utils::is_valid_ip6);
            if (!ipv6s.empty()) {
                return create_aaaarecord_response(request, settings, ipv6s);
            }
        } else if (type == LDNS_RR_TYPE_HTTPS) {
            if (original_response == nullptr) {
                return NeedsResponse{};
            }
            return SvcbHttpsHelpers::modify_response(original_response, ips);
        }
        // empty response
        return create_soa_response(request, settings, SOA_RETRY_DEFAULT);
    }

    /**
     * Create response for request that matched some rules.
     * If rule is Adblock-style or Hosts-rule with "blocking IP", then blocking mode is applied.
     * Otherwise, `create_response_with_ips()` is called.
     */
    static CreateResponseResult create_blocking_response(const ldns_pkt *request, const  ldns_pkt *original_response,
            const DnsProxySettings *settings, const std::vector<const DnsFilter::Rule *> &rules,
            std::optional<DnsFilter::ApplyDnsrewriteResult::RewriteInfo> rewritten_info) {
        const ldns_rr *question = ldns_rr_list_rr(ldns_pkt_question(request), 0);

        if (rewritten_info.has_value()) {
            ldns_pkt *result = create_response_by_request(request);
            ldns_pkt_set_rcode(result, rewritten_info->rcode);
            for (auto &rr : rewritten_info->rrs) {
                if (ldns_rr_get_type(rr.get()) != LDNS_RR_TYPE_CNAME
                        && ldns_rr_get_type(rr.get()) != ldns_rr_get_type(question)) {
                    continue;
                }
                // If this is a CNAME rewrite, then we shouldn't replace the owner
                // of non-CNAME records for the rewritten name.
                if (!rewritten_info->cname.has_value() || ldns_rr_get_type(rr.get()) == LDNS_RR_TYPE_CNAME) {
                    ldns_rdf_deep_free(ldns_rr_owner(rr.get()));
                    ldns_rr_set_owner(rr.get(), ldns_rdf_clone(ldns_rr_owner(question)));
                }
                ldns_rr_set_ttl(rr.get(), settings->blocked_response_ttl_secs);
                ldns_pkt_push_rr(result, LDNS_SECTION_ANSWER, rr.release());
            }
            return ldns_pkt_ptr{result};
        }
        DnsProxyBlockingMode mode;
        const DnsFilter::Rule *effective_rule = rules.front();
        if (nullptr != std::get_if<DnsFilter::AdblockRuleInfo>(&effective_rule->content)) {
            mode = settings->adblock_rules_blocking_mode;
        } else if (rules_contain_blocking_ip(rules)) {
            mode = settings->hosts_rules_blocking_mode;
        } else { // hosts-style IP rule
            return create_response_with_ips(request, original_response, settings, extract_ips(rules));
        }
        CreateResponseResult result;
        switch (mode) {
        case DnsProxyBlockingMode::REFUSED:
            result = create_refused_response(request, settings);
            break;
        case DnsProxyBlockingMode::NXDOMAIN:
            result = create_nxdomain_response(request, settings);
            break;
        case DnsProxyBlockingMode::ADDRESS:
        case DnsProxyBlockingMode::UNSPECIFIED_ADDRESS:
            result = create_address_or_soa_response(
                    request, original_response, settings, mode == DnsProxyBlockingMode::UNSPECIFIED_ADDRESS);
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

    static ldns_pkt_ptr create_arecord_response(const ldns_pkt *request, const DnsProxySettings *settings,
            const std::vector<const char *> &ips) {
        const ldns_rr *question = ldns_rr_list_rr(ldns_pkt_question(request), 0);

        ldns_rr *answer = ldns_rr_new();
        assert(answer != nullptr);
        ldns_rr_set_owner(answer, ldns_rdf_clone(ldns_rr_owner(question)));
        ldns_rr_set_ttl(answer, settings->blocked_response_ttl_secs);
        ldns_rr_set_type(answer, LDNS_RR_TYPE_A);
        ldns_rr_set_class(answer, LDNS_RR_CLASS_IN);
        for (auto *ip : ips) {
            ldns_rdf *rdf = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_A, ip);
            assert(rdf);
            ldns_rr_push_rdf(answer, rdf);
        }

        ldns_pkt *response = create_response_by_request(request);
        ldns_pkt_push_rr(response, LDNS_SECTION_ANSWER, answer);
        return ldns_pkt_ptr{response};
    }

    static ldns_pkt_ptr create_aaaarecord_response(const ldns_pkt *request, const DnsProxySettings *settings,
            const std::vector<const char *> &ips) {
        const ldns_rr *question = ldns_rr_list_rr(ldns_pkt_question(request), 0);

        ldns_rr *answer = ldns_rr_new();
        assert(answer != nullptr);
        ldns_rr_set_owner(answer, ldns_rdf_clone(ldns_rr_owner(question)));
        ldns_rr_set_ttl(answer, settings->blocked_response_ttl_secs);
        ldns_rr_set_type(answer, LDNS_RR_TYPE_AAAA);
        ldns_rr_set_class(answer, LDNS_RR_CLASS_IN);
        for (auto *ip : ips) {
            ldns_rdf *rdf = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_AAAA, ip);
            assert(rdf);
            ldns_rr_push_rdf(answer, rdf);
        }

        ldns_pkt *response = create_response_by_request(request);
        ldns_pkt_push_rr(response, LDNS_SECTION_ANSWER, answer);
        return ldns_pkt_ptr{response};
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
    static CreateResponseResult create_address_or_soa_response(const ldns_pkt *request,
            const ldns_pkt *original_response, const DnsProxySettings *settings, bool force_unspecified_address) {
        ldns_rr *question = ldns_rr_list_rr(ldns_pkt_question(request), 0);
        ldns_rr_type type = ldns_rr_get_type(question);

        switch (type) {
        case LDNS_RR_TYPE_A: {
            if (force_unspecified_address) {
                return create_arecord_response(request, settings, {"0.0.0.0"});
            }
            if (!settings->custom_blocking_ipv4.empty()) {
                assert(utils::is_valid_ip4(settings->custom_blocking_ipv4));
                return create_arecord_response(request, settings, {settings->custom_blocking_ipv4.c_str()});
            }
            if (settings->custom_blocking_ipv6.empty() || is_blocking_ip(settings->custom_blocking_ipv6)) {
                return create_arecord_response(request, settings, {"0.0.0.0"});
            }
            return create_soa_response(request, settings, SOA_RETRY_DEFAULT);
        }
        case LDNS_RR_TYPE_AAAA: {
            if (force_unspecified_address) {
                return create_aaaarecord_response(request, settings, {"::"});
            }
            if (!settings->custom_blocking_ipv6.empty()) {
                assert(utils::is_valid_ip6(settings->custom_blocking_ipv6));
                return create_aaaarecord_response(request, settings, {settings->custom_blocking_ipv6.c_str()});
            }
            if (settings->custom_blocking_ipv4.empty() || is_blocking_ip(settings->custom_blocking_ipv4)) {
                return create_aaaarecord_response(request, settings, {"::"});
            }
            return create_soa_response(request, settings, SOA_RETRY_DEFAULT);
        }
        case LDNS_RR_TYPE_HTTPS: {
            if (!settings->custom_blocking_ipv4.empty() || !settings->custom_blocking_ipv6.empty()) {
                std::vector<const char *> ips;
                if (utils::is_valid_ip4(settings->custom_blocking_ipv4) || !is_blocking_ip(settings->custom_blocking_ipv4)) {
                    ips.push_back(settings->custom_blocking_ipv4.c_str());
                }
                if (utils::is_valid_ip4(settings->custom_blocking_ipv6) || !is_blocking_ip(settings->custom_blocking_ipv4)) {
                    ips.push_back(settings->custom_blocking_ipv6.c_str());
                }
                if (original_response == nullptr) {
                    return NeedsResponse{};
                }
                return SvcbHttpsHelpers::modify_response(original_response, ips);
            }
            return create_soa_response(request, settings, SOA_RETRY_DEFAULT);
        }
        default:
            return create_soa_response(request, settings, SOA_RETRY_DEFAULT);
        }
    }

}; // class ResponseHelpers

} // namespace ag::dns
