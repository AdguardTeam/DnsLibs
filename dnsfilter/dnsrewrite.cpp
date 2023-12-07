#include <algorithm>
#include <cassert>

#include "common/net_utils.h"
#include "common/utils.h"
#include "dns/dnsfilter/dnsfilter.h"

#include "rule_utils.h"

namespace ag::dns::dnsfilter {

struct ApplicableDnsrewriteRules {
    std::vector<const DnsFilter::Rule *> blocking;
    std::vector<const DnsFilter::Rule *> exclusions;
};

static std::optional<ldns_pkt_rcode> parse_rcode(const std::string &part, Logger *log) {
    const ldns_lookup_table *entry = ldns_lookup_by_name(ldns_rcodes, part.c_str());
    if (entry == nullptr) {
        return std::nullopt;
    }

    // LDNS looks up case-insensitively
    if (std::any_of(part.begin(), part.end(), [](char c) -> bool {
            return ::islower(c);
        })) {
        ru_dbglog(log, "RCODE must be in all caps: {}", part);
        return std::nullopt;
    }

    return (ldns_pkt_rcode) entry->id;
}

static std::optional<ldns_rr_type> parse_rrtype(std::string_view part, Logger *log) {
    static constexpr ldns_rr_type SUPPORTED_RR_TYPES[] = {
            LDNS_RR_TYPE_PTR,
            LDNS_RR_TYPE_A,
            LDNS_RR_TYPE_AAAA,
            LDNS_RR_TYPE_CNAME,
            LDNS_RR_TYPE_MX,
            LDNS_RR_TYPE_TXT,
            LDNS_RR_TYPE_HTTPS,
            LDNS_RR_TYPE_SVCB,
    };

    ldns_rr_type type = ldns_get_rr_type_by_name(std::string(part).c_str());
    if (std::end(SUPPORTED_RR_TYPES) == std::find(SUPPORTED_RR_TYPES, std::end(SUPPORTED_RR_TYPES), type)) {
        ru_dbglog(log, "Unsupported RR type: {}", part);
        return std::nullopt;
    }

    return type;
}

static std::optional<rule_utils::DnsrewriteMXValue> parse_mx(std::string_view str, Logger *log) {
    std::array mx_parts = ag::utils::split2_by(str, ' ');

    std::string pref_str{mx_parts[0]};
    char *end = nullptr;
    auto pref = std::strtoul(pref_str.c_str(), &end, 10);
    if (end != &pref_str.back() + 1 || pref > UINT16_MAX) {
        ru_dbglog(log, "Invalid preference value: {}", mx_parts[0]);
        return std::nullopt;
    }

    if (!rule_utils::is_domain_name(mx_parts[1])) {
        ru_dbglog(log, "Invalid mail name: {}", mx_parts[1]);
        return std::nullopt;
    }

    return rule_utils::DnsrewriteMXValue{(uint16_t) pref, std::string(mx_parts[1])};
}

static std::optional<rule_utils::DnsrewriteSVCBValue> parse_svcb(std::string_view str, Logger *log) {
    std::array parts = ag::utils::split2_by(str, ' ');

    std::string priority_str{parts[0]};
    char *end = nullptr;
    auto priority = std::strtoul(priority_str.c_str(), &end, 10);
    if (end != &priority_str.back() + 1 || priority > UINT16_MAX) {
        ru_dbglog(log, "Invalid priority value: {}", parts[0]);
        return std::nullopt;
    }

    parts = ag::utils::split2_by(parts[1], ' ');
    // https://tools.ietf.org/html/draft-ietf-dnsop-svcb-httpssvc-03#section-2.6.1
    if (parts[0] != "." && !rule_utils::is_domain_name(parts[0])) {
        ru_dbglog(log, "Invalid target domain: {}", parts[0]);
        return std::nullopt;
    }

    ldns_rdf *rd;
    ldns_status status = ldns_str2rdf_svcparams(&rd, std::string(parts[1]).c_str());
    if (status != LDNS_STATUS_OK) {
        ru_dbglog(log, "Invalid values part: {} ({})", parts[1], magic_enum::enum_name(status));
        return std::nullopt;
    }

    rule_utils::DnsrewriteSVCBValue value = {};
    value.priority = priority;
    value.domain = std::string(parts[0]);
    value.values.reset(rd);

    return value;
}

static std::pair<bool, std::optional<rule_utils::DnsrewriteInfo>> parse_parameters(
        std::string_view params, Logger *log) {
    enum part_idx {
        DRPI_RCODE,
        DRPI_RRTYPE,
        DRPI_VALUE,
    };

    static constexpr char PARTS_DELIM = ';';
    static constexpr size_t SHORTHAND_PARTS_NUM = 1;
    static constexpr size_t FULLY_QUALIFIED_PARTS_NUM = magic_enum::enum_count<part_idx>();

    std::vector parts =
            !params.empty() ? ag::utils::split_by(params, PARTS_DELIM, true) : std::vector<std::string_view>{};
    if (!parts.empty() && parts.size() != SHORTHAND_PARTS_NUM && parts.size() != FULLY_QUALIFIED_PARTS_NUM) {
        ru_dbglog(log, "Wrong number of parts: {}", parts.size());
        return {false, std::nullopt};
    }

    std::optional<rule_utils::DnsrewriteInfo> info;
    auto get_info = [&info]() -> rule_utils::DnsrewriteInfo & {
        if (!info.has_value()) {
            info.emplace();
        }
        return info.value();
    };

    switch (parts.size()) {
    case 0: {
        break;
    }
    case SHORTHAND_PARTS_NUM: {
        // do not log the try
        if (auto rrtype = parse_rrtype(parts[0], nullptr); rrtype.has_value()) {
            ru_dbglog(log, "Unexpected parameter in shorthand syntax: {}", parts[0]);
            return {false, std::nullopt};
        }

        if (auto rcode = parse_rcode(std::string(parts[0]), log); rcode.has_value()) {
            get_info().rcode = rcode.value();
        } else {
            get_info().value = parts[0];
        }
        break;
    }
    case FULLY_QUALIFIED_PARTS_NUM: {
        for (size_t i = 0; i < FULLY_QUALIFIED_PARTS_NUM; ++i) {
            switch ((part_idx) i) {
            case DRPI_RCODE:
                if (parts[i].empty()) {
                    continue;
                }
                if (auto rcode = parse_rcode(std::string(parts[i]), log); rcode.has_value()) {
                    get_info().rcode = rcode.value();
                    continue;
                }
                break;
            case DRPI_RRTYPE:
                if (parts[i].empty()) {
                    continue;
                }
                if (auto rrtype = parse_rrtype(parts[i], log); rrtype.has_value()) {
                    get_info().rrtype = rrtype.value();
                    continue;
                }
                break;
            case DRPI_VALUE:
                get_info().value = parts[i];
                continue;
            }
            ru_dbglog(log, "Unexpected parameter at {} position: {}", i + 1, parts[i]);
            return {false, std::nullopt};
        }
        break;
    }
    }

    return {true, std::move(info)};
}

static bool parse_value_by_rrtype(
        rule_utils::DnsrewriteInfo &info, const rule_utils::MatchInfo &match_info, Logger *log) {
    switch (info.rrtype.value()) {
    case LDNS_RR_TYPE_PTR: {
        if (std::string_view domain = info.value; domain.empty() || domain.back() != '.'
                || !rule_utils::is_domain_name(domain.substr(0, domain.length() - 1))) {
            ru_dbglog(log, "Invalid domain name");
            return false;
        }

        bool is_valid_pattern = !match_info.has_wildcard && !match_info.is_regex_rule
                && (match_info.pattern_mode
                        & (rule_utils::MPM_LINE_START_ASSERTED | rule_utils::MPM_DOMAIN_START_ASSERTED))
                && (match_info.pattern_mode & rule_utils::MPM_LINE_END_ASSERTED)
                && (match_info.text.ends_with(rule_utils::REVERSE_DNS_DOMAIN_SUFFIX)
                        || match_info.text.ends_with(rule_utils::REVERSE_IPV6_DNS_DOMAIN_SUFFIX));
        if (!is_valid_pattern) {
            ru_dbglog(log, "Invalid rule pattern for such kind of RR type");
            return false;
        }
        break;
    }
    case LDNS_RR_TYPE_CNAME: {
        std::string_view value = info.value;
        if (!value.empty() && value.back() == '.') {
            value.remove_suffix(1);
        }
        if (!rule_utils::is_domain_name(value)) {
            ru_dbglog(log, "Value doesn't correspond to RR type");
            return false;
        }
        break;
    }
    case LDNS_RR_TYPE_A: {
        if (SocketAddress addr = ag::utils::str_to_socket_address(info.value);
                !addr.valid() || addr.is_ipv6() || addr.port() != 0) {
            ru_dbglog(log, "Invalid IP address in value");
            return false;
        }
        break;
    }
    case LDNS_RR_TYPE_AAAA: {
        if (SocketAddress addr = ag::utils::str_to_socket_address(info.value);
                !addr.valid() || !addr.is_ipv6() || addr.port() != 0) {
            ru_dbglog(log, "Invalid IP address in value");
            return false;
        }
        break;
    }
    case LDNS_RR_TYPE_MX: {
        auto mx = parse_mx(info.value, log);
        if (!mx.has_value()) {
            ru_dbglog(log, "Invalid MX value");
            return false;
        }

        info.parsed_value = std::move(mx.value());
        break;
    }
    case LDNS_RR_TYPE_TXT:
        break; // nothing to validate
    case LDNS_RR_TYPE_HTTPS:
    case LDNS_RR_TYPE_SVCB: {
        auto svcb = parse_svcb(info.value, log);
        if (!svcb.has_value()) {
            ru_dbglog(log, "Invalid SVCB(HTTPS) value");
            return false;
        }

        info.parsed_value = std::move(svcb.value());
        break;
    }
    default:
        assert(0);
        return false;
    }

    return true;
}

bool rule_utils::parse_dnsrewrite_modifier(
        Rule &rule, std::string_view params_str, const MatchInfo &match_info, Logger *log) {
    auto [success, info] = parse_parameters(params_str, log);
    if (!success) {
        return false;
    }

    const auto &content = std::get<DnsFilter::AdblockRuleInfo>(rule.public_part.content);
    if (!info.has_value()) {
        if (!content.props.test(DnsFilter::DARP_EXCEPTION)) {
            info.emplace();
        }
    } else if (info->rrtype.has_value()) {
        if (!parse_value_by_rrtype(info.value(), match_info, log)) {
            ru_dbglog(log, "Invalid RR type in parameters: {}", params_str);
            return false;
        }
    } else if (info->value.empty()) {
        // do nothing
    } else if (std::string_view value = info->value;
               is_domain_name(value) || is_domain_name(value.substr(0, value.length() - 1))) {
        info->rrtype = LDNS_RR_TYPE_CNAME;
    } else if (SocketAddress addr = ag::utils::str_to_socket_address(info->value); addr.is_ipv6()) {
        info->rrtype = LDNS_RR_TYPE_AAAA;
    } else if (addr.valid()) {
        info->rrtype = LDNS_RR_TYPE_A;
    } else {
        ru_dbglog(log, "Unexpected value part: {}", params_str);
        return false;
    }

    content.params->dnsrewrite = std::move(info);

    return true;
}

// Return true if the left rule prevails over the right one
static bool has_higher_priority(const DnsFilter::Rule *l, const DnsFilter::Rule *r) {
    const auto &linfo = std::get<DnsFilter::AdblockRuleInfo>(l->content).params->dnsrewrite.value();
    const auto &rinfo = std::get<DnsFilter::AdblockRuleInfo>(r->content).params->dnsrewrite.value();

    return (linfo.rcode != LDNS_RCODE_NOERROR && rinfo.rcode == LDNS_RCODE_NOERROR)
            || (linfo.rrtype == LDNS_RR_TYPE_CNAME && rinfo.rrtype != LDNS_RR_TYPE_CNAME);
}

static ApplicableDnsrewriteRules get_applicable_rules(const std::vector<const DnsFilter::Rule *> &rules) {
    using Rule = DnsFilter::Rule;

    ApplicableDnsrewriteRules applicable_rules;
    applicable_rules.blocking.reserve(rules.size());
    for (const Rule *r : rules) {
        if (const auto &info = std::get<DnsFilter::AdblockRuleInfo>(r->content);
                !info.props.test(DnsFilter::DARP_EXCEPTION)) {
            applicable_rules.blocking.emplace_back(r);
        } else {
            applicable_rules.exclusions.emplace_back(r);
        }
    }

    for (auto i = applicable_rules.blocking.begin(); i != applicable_rules.blocking.end();) {
        auto found_exclusion = std::find_if(applicable_rules.exclusions.cbegin(), applicable_rules.exclusions.cend(),
                [blocking = *i](const Rule *exclusion) {
                    const auto &blocking_info = std::get<DnsFilter::AdblockRuleInfo>(blocking->content);
                    const auto &exclusion_info = std::get<DnsFilter::AdblockRuleInfo>(exclusion->content);
                    // an exclusion beats a blocking rule if
                    // 1) the blocking is less `$important`
                    return (exclusion_info.props.test(DnsFilter::DARP_IMPORTANT)
                                   && !blocking_info.props.test(DnsFilter::DARP_IMPORTANT))
                            // 2) the exclusion has no parameters (`@@example.com$dnsrewrite`)
                            || !exclusion_info.params->dnsrewrite.has_value()
                            // 3) the exclusion parameters match the blocking ones
                            //    (`@@example.com$dnsrewrite=127.0.0.1` vs `example.com$dnsrewrite=127.0.0.1`)
                            || exclusion_info.params->dnsrewrite.value() == blocking_info.params->dnsrewrite.value();
                });
        if (found_exclusion == applicable_rules.exclusions.cend()) {
            ++i;
        } else {
            i = applicable_rules.blocking.erase(i);
        }
    }

    std::sort(applicable_rules.blocking.begin(), applicable_rules.blocking.end(), has_higher_priority);

    if (applicable_rules.blocking.size() > 1) {
        const auto &info =
                std::get<DnsFilter::AdblockRuleInfo>(applicable_rules.blocking[0]->content).params->dnsrewrite.value();
        if (info.rcode != LDNS_RCODE_NOERROR || info.rrtype == LDNS_RR_TYPE_CNAME) {
            applicable_rules.blocking.resize(1);
        }
    }

    return applicable_rules;
}

} // namespace ag::dns::dnsfilter

namespace ag::dns {

using namespace dnsfilter;

DnsFilter::ApplyDnsrewriteResult DnsFilter::apply_dnsrewrite_rules(const std::vector<const Rule *> &rules) {
    using Rule = DnsFilter::Rule;

    ApplicableDnsrewriteRules applicable_rules = get_applicable_rules(rules);

    ApplyDnsrewriteResult result;
    result.rules.reserve(applicable_rules.blocking.size() + applicable_rules.exclusions.size());

    for (const Rule *r : applicable_rules.blocking) {
        const auto &rule_info = std::get<DnsFilter::AdblockRuleInfo>(r->content);
        const rule_utils::DnsrewriteInfo &dnsrewrite = rule_info.params->dnsrewrite.value();

        auto &rewr_info = result.rewritten_info;
        if (!rewr_info.has_value()) {
            rewr_info.emplace(ApplyDnsrewriteResult::RewriteInfo{});
            rewr_info->rcode = dnsrewrite.rcode;
        } else {
            assert(rewr_info->rcode == dnsrewrite.rcode);
        }

        if (!dnsrewrite.rrtype.has_value()) {
            continue;
        }

        ldns_rr *rr = rewr_info->rrs.emplace_back(ldns_rr_new()).get();
        ldns_rr_set_type(rr, dnsrewrite.rrtype.value());

        ldns_rdf *rdfs[3] = {};

        switch (dnsrewrite.rrtype.value()) {
        case LDNS_RR_TYPE_CNAME:
            rewr_info->cname = dnsrewrite.value;
            [[fallthrough]];
        case LDNS_RR_TYPE_PTR:
            rdfs[0] = ldns_dname_new_frm_str(dnsrewrite.value.c_str());
            break;
        case LDNS_RR_TYPE_A:
            rdfs[0] = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_A, dnsrewrite.value.c_str());
            break;
        case LDNS_RR_TYPE_AAAA:
            rdfs[0] = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_AAAA, dnsrewrite.value.c_str());
            break;
        case LDNS_RR_TYPE_MX: {
            const auto &mx = std::get<rule_utils::DnsrewriteMXValue>(dnsrewrite.parsed_value);
            rdfs[0] = ldns_native2rdf_int16(LDNS_RDF_TYPE_INT16, mx.preference);
            rdfs[1] = ldns_dname_new_frm_str(mx.exchange.c_str());
            break;
        }
        case LDNS_RR_TYPE_TXT: {
            rdfs[0] = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_STR, dnsrewrite.value.c_str());
            break;
        }
        case LDNS_RR_TYPE_HTTPS:
        case LDNS_RR_TYPE_SVCB: {
            const auto &svcb = std::get<rule_utils::DnsrewriteSVCBValue>(dnsrewrite.parsed_value);
            rdfs[0] = ldns_native2rdf_int16(LDNS_RDF_TYPE_INT16, svcb.priority);
            rdfs[1] = ldns_dname_new_frm_str(svcb.domain.c_str());
            rdfs[2] = ldns_rdf_clone(svcb.values.get());
            break;
        }
        default:
            assert(0);
            break;
        }

        for (size_t i = 0; i < std::size(rdfs) && rdfs[i] != nullptr; ++i) {
            ldns_rdf *rdf = rdfs[i];
            ldns_rr_push_rdf(rr, rdf);
        }
    }

    result.rules.insert(result.rules.end(), applicable_rules.blocking.begin(), applicable_rules.blocking.end());
    result.rules.insert(result.rules.end(), applicable_rules.exclusions.begin(), applicable_rules.exclusions.end());

    return result;
}

} // namespace ag::dns
