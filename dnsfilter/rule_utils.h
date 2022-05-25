#pragma once


#include <string_view>
#include <string>
#include <optional>
#include <vector>
#include <variant>
#include "common/logger.h"
#include "dnsfilter/dnsfilter.h"


/**
 *  Set of helper functions to manage the rules
 *  Useful links:
 *   - https://github.com/AdguardTeam/AdguardHome/wiki/Hosts-Blocklists
 */
namespace ag::dnsfilter::rule_utils {

static constexpr std::string_view REVERSE_DNS_DOMAIN_SUFFIX = ".in-addr.arpa.";
static constexpr std::string_view REVERSE_IPV6_DNS_DOMAIN_SUFFIX = ".ip6.arpa.";

#define ru_dbglog(l_, ...) do { if ((l_) != nullptr) dbglog(*(l_), __VA_ARGS__); } while (0)

struct DnstypeInfo {
    enum MatchMode {
        DTMM_ENABLE, // `types` is the list of the affected ones
        DTMM_EXCLUDE, // `types` is the list of the non-affected ones
    };

    /** List of the query types affected by the rule. Empty means any. */
    std::vector<ldns_rr_type> types;
    MatchMode mode = DTMM_ENABLE;
};

// https://tools.ietf.org/html/rfc1035#section-3.3.9
struct DnsrewriteMXValue {
    uint16_t preference;
    std::string exchange;
};

// https://tools.ietf.org/html/draft-ietf-dnsop-svcb-httpssvc-03#section-2.2
struct DnsrewriteSVCBValue {
    using ldns_rdf_ptr = UniquePtr<ldns_rdf, &ldns_rdf_deep_free>;

    uint16_t priority = 0;
    std::string domain;
    ldns_rdf_ptr values;

    DnsrewriteSVCBValue() = default;
    ~DnsrewriteSVCBValue() = default;
    DnsrewriteSVCBValue(DnsrewriteSVCBValue &&) = default;
    DnsrewriteSVCBValue &operator=(DnsrewriteSVCBValue &&) = default;

    DnsrewriteSVCBValue(const DnsrewriteSVCBValue &other) {
        *this = other;
    }

    DnsrewriteSVCBValue &operator=(const DnsrewriteSVCBValue &other) {
        this->priority = other.priority;
        this->domain = other.domain;
        if (other.values != nullptr) {
            this->values.reset(ldns_rdf_clone(other.values.get()));
        }
        return *this;
    }
};

struct DnsrewriteInfo {
    using ParsedValueType = std::variant<
            /** RR type is MX */
            DnsrewriteMXValue,
            /** RR type is SVCB or HTTPS */
            DnsrewriteSVCBValue,
            /** other types come as raw strings */
            std::monostate>;

    ldns_pkt_rcode rcode = LDNS_RCODE_NOERROR;
    std::optional<ldns_rr_type> rrtype;
    std::string value;
    ParsedValueType parsed_value;

    bool operator==(const DnsrewriteInfo &other) const {
        // not comparing `parsed_value` fields here intentionally,
        // because they are checked automatically by comparison of the `value` fields
        return this->rcode == other.rcode
                && this->rrtype == other.rrtype
                && this->value == other.value;
    }
};

struct Rule {
    enum MatchMethodId {
        /// match by comparing the domain's string repesentation against the rule domain string
        MMID_EXACT,
        /// a domain can be matched against such rule by comparing
        /// with items of `matching_parts`, if it's equal to any it's matched
        MMID_SUBDOMAINS,
        /// a domain can be matched against such rule, if it contains each item
        /// of `matching_parts` in corresponding order
        /// (e.g. `example*.org` -> { `example`, `.org` })
        MMID_SHORTCUTS,
        /// a domain can be matched against such rule only by applying the regex
        MMID_REGEX,
        /// an optimized version of `MMID_REGEX` (as regex applying
        /// is pretty expensive operation): if it's possible
        /// some shortcuts will be extracted from a rule (e.g.
        /// `/exampl.*\.com/` -> { `exampl`, `.com` }), and if a domain
        /// contains these shortcuts in corresponding order and matches
        /// the regex, it is matched against the rule
        MMID_SHORTCUTS_AND_REGEX,
    };

    // public part of rule structure (see `ag::DnsFilter::Rule`)
    DnsFilter::Rule public_part;
    // see `match_method_id`
    MatchMethodId match_method;
    // list of matching parts accordingly to `match_method` value
    std::vector<std::string> matching_parts;
    // non-nullopt if the rule has `$dnstype` modifier
    std::optional<DnstypeInfo> dnstype;
};


/**
 * Check if string is a commentary
 */
static inline bool is_comment(std::string_view str) {
    return str[0] == '!' || str[0] == '#';
}

/**
 * Parse rule from given string
 * @param[in]  str   input string
 * @param[in]  log   logger (if null, rule parsing errors won't be logged)
 * @return     A rule if parsed successfully,
 *             nullopt otherwise
 */
std::optional<Rule> parse(std::string_view str, Logger *log = nullptr);

/**
 * Extract a regular expression text from rule
 * @param[in]  r     rule
 * @return     Regular expression text
 */
std::string get_regex(const Rule &r);

/**
 * Generate the rule text without badfilter modifier
 * @param[in]  r     rule
 * @return     Text without badfilter modifier
 */
std::string get_text_without_badfilter(const DnsFilter::Rule &r);

enum match_pattern_mode {
    MPM_NONE = 0,
    /** `ample.org` should not match `example.org` (e.g. `|ample.org`) */
    MPM_LINE_START_ASSERTED = 1 << 0,
    /** `exampl` should not match `example.org` (e.g. `exampl|`) */
    MPM_LINE_END_ASSERTED = 1 << 1,
    /**
     * `example.org` should not match `eeexample.org`,
     * but should match `sub.example.org` (e.g. `||example.org`)
     */
    MPM_DOMAIN_START_ASSERTED = 1 << 2,
};

struct MatchInfo {
    std::string_view text; // matching text without all prefixes
    bool is_regex_rule; // whether the original rule is a regex rule
    bool has_wildcard;
    int pattern_mode; // see `match_pattern_mode`
};

/**
 * Parse `$dnsrewrite` modifier parameters
 * https://github.com/AdguardTeam/AdguardHome/wiki/Hosts-Blocklists#dnsrewrite
 * @return true if successful
 */
bool parse_dnsrewrite_modifier(rule_utils::Rule &rule, std::string_view params_str,
        const MatchInfo &match_info, Logger *log);

/**
 * Check if the string is a domain name
 */
bool is_domain_name(std::string_view str);

} // namespace ag::dnsfilter::rule_utils

namespace ag {

struct DnsFilter::AdblockRuleInfo::Parameters {
    // non-nullopt if the rule has `$dnsrewrite` modifier
    std::optional<ag::dnsfilter::rule_utils::DnsrewriteInfo> dnsrewrite;
};

} // namespace ag