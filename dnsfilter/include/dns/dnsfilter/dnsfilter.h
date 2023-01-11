#pragma once


#include <optional>
#include <string>
#include <vector>
#include <variant>
#include <bitset>
#include <tuple>
#include <memory>
#include <magic_enum.hpp>
#include <ldns/ldns.h>

#include "common/error.h"
#include "common/defs.h"

#include "dns/common/dns_defs.h"
#include "dns/proxy/dnsproxy_events.h"

namespace ag::dns {

/**
 * The DNS filter entity is intended to hold rules, match them against domains and manage
 * the matched ones to determine if a request for such domain should be blocked.
 */
class DnsFilter {
public:
    using Handle = void *;

    using DnsFilterResult = std::pair<Handle, Error<DnsProxyInitError>>;

    struct FilterParams {
        int32_t id{0}; // filter id
        std::string data; // path to file with rules or actual rules
        bool in_memory{false}; // if true, data is actual rules, otherwise data is path to file with rules
        SystemTime mtime;  // time of last modification of file with rule
    };

    struct EngineParams {
        std::vector<FilterParams> filters; // filter list
        size_t mem_limit{0}; // the upper limit, in bytes, on the filtering engine memory usage, 0 means no limit
    };

    enum AdblockRuleProps {
        DARP_EXCEPTION, // is exceptional (starts with `@@`)
        DARP_IMPORTANT, // has `$important` modifier
        DARP_BADFILTER, // has `$badfilter` modifier
        DARP_DNSTYPE, // has `$dnstype` modifier
        DARP_DNSREWRITE, // has `$dnsrewrite` modifier
        DARP_DENYALLOW, // has `$denyallow` modifier
    };

    // Both https://github.com/AdguardTeam/AdguardHome/wiki/Hosts-Blocklists#adblock-style
    // and https://github.com/AdguardTeam/AdguardHome/wiki/Hosts-Blocklists#domains-only
    struct AdblockRuleInfo {
        using PropsSet = std::bitset<magic_enum::enum_count<AdblockRuleProps>()>;
        struct Parameters;

        PropsSet props; // properties (see `adblock_rule_props`)
        Parameters *params = nullptr; // parsed parameters

        AdblockRuleInfo() = default;
        explicit AdblockRuleInfo(PropsSet props);
        ~AdblockRuleInfo();

        AdblockRuleInfo(AdblockRuleInfo &&) noexcept;
        AdblockRuleInfo &operator=(AdblockRuleInfo &&) noexcept;
        AdblockRuleInfo(const AdblockRuleInfo &other);
        AdblockRuleInfo &operator=(const AdblockRuleInfo &other);
    };

    // https://github.com/AdguardTeam/AdguardHome/wiki/Hosts-Blocklists#etc-hosts
    struct HostsRuleInfo {
        std::string ip;
    };

    struct Rule {
        using ContentType = std::variant<AdblockRuleInfo, HostsRuleInfo>;

        int32_t filter_id; // id of a filter which contains the matched rule
        std::string text; // rule text
        ContentType content; // rule type specific info
    };

    struct MatchParam {
        /** A domain to check */
        std::string_view domain;
        /** A query RR type */
        ldns_rr_type rr_type;
    };

    DnsFilter();
    DnsFilter(const DnsFilter &) = delete;
    DnsFilter(DnsFilter &&) = delete;

    ~DnsFilter();

    DnsFilter &operator=(const DnsFilter &) = delete;
    DnsFilter &operator=(DnsFilter &&) = delete;

    /**
     * Create filtering engine handle
     * @param[in]  p     engine parameters
     * @return     An engine handle with an optional warning string, or
     *             error string
     */
    [[nodiscard]] DnsFilterResult create(const EngineParams &p);

    /**
     * Destroy filtering engine handle
     * @param[in]  obj   handle
     */
    void destroy(Handle obj);

    /**
     * Match domain against added rules
     * @param[in]  obj     filtering engine handle
     * @param[in]  param   see `match_param`
     * @return     List of matched rules (please note, that it contains all matched rules
     *             in undefined order, so the one should use `get_effective_rule` to get
     *             the rule, which should be considered in request blocking logic)
     */
    std::vector<Rule> match(Handle obj, MatchParam param);

    struct EffectiveRules {
        /** `$dnsrewrite` rules are special */
        std::vector<const Rule *> dnsrewrite;
        /**
         * All other rules. Contains the rules which have equal priority and the same kind.
         * For example, if the following rules were matched:
         *    `example.com`, `@@example.com` and `@@example.com$dnstype=a`,
         * the leftovers list would contain: `@@example.com` and `@@example.com$dnstype=a`.
         */
        std::vector<const Rule *> leftovers;
    };

    /**
     * Select the rules which should be applied to the request
     * @detail     In the case of several rules which have hosts file syntax were matched this
     *             function returns all those rules. In other cases returns just the only rule.
     * @param[in]  rules  matched rules
     * @return     Selected rules
     */
    static EffectiveRules get_effective_rules(const std::vector<Rule> &rules);

    /**
     * Check if string is a valid rule
     * @param str string to check
     * @return true if string is a valid rule, false otherwise
     */
    static bool is_valid_rule(std::string_view str);

    enum RuleGenerationOptions : uint32_t {
        RGO_IMPORTANT = 1u << 0, /**< Add an $important modifier. */
        RGO_DNSTYPE = 1u << 1,   /**< Add a $dnstype modifier. */
    };

    struct RuleTemplate {
        std::string text;

        RuleTemplate() = default;
        explicit RuleTemplate(std::string text);

        RuleTemplate(const RuleTemplate &) = default;
        RuleTemplate &operator=(const RuleTemplate &) = default;

        RuleTemplate(RuleTemplate &&) = default;
        RuleTemplate &operator=(RuleTemplate &&) = default;
    };

    struct FilteringLogAction {
        std::vector<RuleTemplate> templates; /**< A set of rule templates. */
        uint32_t allowed_options = 0;        /**< Options that are allowed to be passed to `generate_rule`. */
        uint32_t required_options = 0;       /**< Options that are required for the generated rule to be correct. */
        bool blocking = false; /**< Whether something will be blocked or un-blocked as a result of this action. */
    };

    /** Suggest an action based on filtering event. */
    static std::optional<FilteringLogAction> suggest_action(const DnsRequestProcessedEvent &event);

    /**
     * Generate a rule based on a tempalte from `FilteringLogAction`, a set of options,
     * and the event for which the action was suggested.
     */
    static std::string generate_rule(
            const RuleTemplate &rule_template, const DnsRequestProcessedEvent &event, uint32_t options);

    struct ApplyDnsrewriteResult {
        struct RewriteInfo {
            using ldns_rr_ptr = UniquePtr<ldns_rr, &ldns_rr_free>;

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
        std::vector<const Rule *> rules;
        /** The rules applying result. nullopt if nothing to rewrite. */
        std::optional<RewriteInfo> rewritten_info;
    };

    /**
     * Forge a result basing on the list of matched `$dnsrewrite` rules
     * @param rules the rules to apply
     * @return see `apply_dnsrewrite_result`
     */
    static ApplyDnsrewriteResult apply_dnsrewrite_rules(const std::vector<const Rule *> &rules);
};

} // namespace ag::dns