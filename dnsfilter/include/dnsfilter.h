#pragma once


#include <string>
#include <vector>
#include <variant>
#include <bitset>
#include <tuple>
#include <memory>
#include <ag_defs.h>
#include <magic_enum.hpp>
#include <ldns/ldns.h>


namespace ag {

/**
 * The DNS filter entity is intended to hold rules, match them against domains and manage
 * the matched ones to determine if a request for such domain should be blocked.
 */
class dnsfilter {
public:
    using handle = void*;

    struct filter_params {
        int32_t id{0}; // filter id
        std::string data; // path to file with rules or actual rules
        bool in_memory{false}; // if true, data is actual rules, otherwise data is path to file with rules
        time_t mtime{0};  // time of last modification of file with rule
    };

    struct engine_params {
        std::vector<filter_params> filters; // filter list
        size_t mem_limit{0}; // the upper limit, in bytes, on the filtering engine memory usage, 0 means no limit
    };

    enum adblock_rule_props {
        DARP_EXCEPTION, // is exceptional (starts with `@@`)
        DARP_IMPORTANT, // has `$important` modifier
        DARP_BADFILTER, // has `$badfilter` modifier
        DARP_DNSTYPE, // has `$dnstype` modifier
        DARP_DNSREWRITE, // has `$dnsrewrite` modifier
    };

    // Both https://github.com/AdguardTeam/AdguardHome/wiki/Hosts-Blocklists#adblock-style
    // and https://github.com/AdguardTeam/AdguardHome/wiki/Hosts-Blocklists#domains-only
    struct adblock_rule_info {
        using props_set = std::bitset<magic_enum::enum_count<adblock_rule_props>()>;
        struct parameters;

        props_set props; // properties (see `adblock_rule_props`)
        parameters *params = nullptr; // parsed parameters

        adblock_rule_info() = default;
        explicit adblock_rule_info(props_set props);
        ~adblock_rule_info();

        adblock_rule_info(adblock_rule_info &&);
        adblock_rule_info &operator=(adblock_rule_info &&);
        adblock_rule_info(const adblock_rule_info &other);
        adblock_rule_info &operator=(const adblock_rule_info &other);
    };

    // https://github.com/AdguardTeam/AdguardHome/wiki/Hosts-Blocklists#etc-hosts
    struct etc_hosts_rule_info {
        std::string ip;
    };

    struct rule {
        using content_type = std::variant<adblock_rule_info, etc_hosts_rule_info>;

        int32_t filter_id; // id of a filter which contains the matched rule
        std::string text; // rule text
        content_type content; // rule type specific info
    };

    struct match_param {
        /** A domain to check */
        std::string_view domain;
        /** A query RR type */
        ldns_rr_type rr_type;
    };

    dnsfilter();
    dnsfilter(const dnsfilter &) = delete;
    dnsfilter(dnsfilter &&) = delete;

    ~dnsfilter();

    dnsfilter &operator=(const dnsfilter &) = delete;
    dnsfilter &operator=(dnsfilter &&) = delete;

    /**
     * Create filtering engine handle
     * @param[in]  p     engine parameters
     * @return     An engine handle with an optional warning string, or
     *             nullptr with an error string
     */
    std::pair<handle, err_string> create(const engine_params &p);

    /**
     * Destroy filtering engine handle
     * @param[in]  obj   handle
     */
    void destroy(handle obj);

    /**
     * Match domain against added rules
     * @param[in]  obj     filtering engine handle
     * @param[in]  param   see `match_param`
     * @return     List of matched rules (please note, that it contains all matched rules
     *             in undefined order, so the one should use `get_effective_rule` to get
     *             the rule, which should be considered in request blocking logic)
     */
    std::vector<rule> match(handle obj, match_param param);

    struct effective_rules {
        /** `$dnsrewrite` rules are special */
        std::vector<const rule *> dnsrewrite;
        /**
         * All other rules. Contains the rules which have equal priority and the same kind.
         * For example, if the following rules were matched:
         *    `example.com`, `@@example.com` and `@@example.com$dnstype=a`,
         * the leftovers list will contain: `@@example.com` and `@@example.com$dnstype=a`.
         */
        std::vector<const rule *> leftovers;
    };

    /**
     * Select the rules which should be applied to the request
     * @detail     In the case of several rules which have hosts file syntax were matched this
     *             function returns all those rules. In other cases returns just the only rule.
     * @param[in]  rules  matched rules
     * @return     Selected rules
     */
    static effective_rules get_effective_rules(const std::vector<rule> &rules);

    /**
     * Check if string is a valid rule
     * @param str string to check
     * @return true if string is a valid rule, false otherwise
     */
    static bool is_valid_rule(std::string_view str);

    struct apply_dnsrewrite_result {
        struct rewrite_info {
            using ldns_rr_ptr = std::unique_ptr<ldns_rr, ag::ftor<&ldns_rr_free>>;

            /** The rcode which should be set to the answer */
            ldns_pkt_rcode rcode = LDNS_RCODE_NOERROR;
            /** The RR list which should be added to the answer section if non-empty */
            std::vector<ldns_rr_ptr> rrs;
            /**
             * The domain name to be resolved instead of the original one.
             * In case it is non-nullopt, the proxy should resolve it and add the `rr_list`
             * to the answer instead of blocking it immediately.
             */
            std::optional<std::string> cname;
        };

        /** The list of applied rules */
        std::vector<const rule *> rules;
        /** The rules applying result. nullopt if nothing to rewrite. */
        std::optional<rewrite_info> rewritten_info;
    };

    /**
     * Forge a result basing on the list of matched `$dnsrewrite` rules
     * @param rules the rules to apply
     * @return see `apply_dnsrewrite_result`
     */
    static apply_dnsrewrite_result apply_dnsrewrite_rules(const std::vector<const rule *> &rules);
};

} // namespace ag
