#pragma once


#include <string>
#include <vector>
#include <optional>
#include <bitset>
#include <tuple>
#include <ag_defs.h>


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
    };

    struct engine_params {
        std::vector<filter_params> filters; // filter list
        size_t mem_limit{0}; // the upper limit, in bytes, on the filtering engine memory usage, 0 means no limit
    };

    enum rule_props {
        RP_EXCEPTION, // is exceptional (starts with `@@`)
        RP_IMPORTANT, // has `$important` modifier
        RP_BADFILTER, // has `$badfilter` modifier
        RP_NUM
    };

    struct rule {
        int32_t filter_id; // id of a filter which contains the matched rule
        std::string text; // rule text
        std::bitset<RP_NUM> props; // properties (see `rule_props`)
        std::optional<std::string> ip; // non-nullopt if the rule has hosts syntax
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
     * @param[in]  domain  domain to be matched
     * @return     List of matched rules (please note, that it contains all matched rules
     *             in undefined order, so the one should use `get_effective_rule` to get
     *             the rule, which should be considered in request blocking logic)
     */
    std::vector<rule> match(handle obj, std::string_view domain);

    /**
     * Select the rules which should be applied to the request
     * @detail     In the case of several rules which have hosts file syntax were matched this
     *             function returns all those rules. In other cases returns just the only rule.
     * @param[in]  rules  matched rules
     * @return     Selected rules
     */
    static std::vector<const rule *> get_effective_rules(const std::vector<rule> &rules);

    /**
     * Check if string is a valid rule
     * @param str string to check
     * @return true if string is a valid rule, false otherwise
     */
    static bool is_valid_rule(std::string_view str);
};

} // namespace ag
