#pragma once


#include <string>
#include <vector>
#include <optional>
#include <bitset>


namespace ag {

/**
 * The DNS filter entity is intended to hold rules, match them against domains and manage
 * the matched ones to determine if a request for such domain should be blocked.
 */
class dnsfilter {
public:
    using handle = void*;

    struct filter_params {
        uint32_t id; // filter id
        std::string path; // path to file with rules
    };

    struct engine_params {
        std::vector<filter_params> filters; // filter list
    };

    enum rule_props {
        RP_EXCEPTION, // is exceptional (starts with `@@`)
        RP_IMPORTANT, // has `$important` modifier
        RP_BADFILTER, // has `$badfilter` modifier
        RP_NUM
    };

    struct rule {
        uint32_t filter_id; // id of a filter which contains the matched rule
        std::string text; // rule text
        std::bitset<RP_NUM> props; // properties (see `rule_props`)
    };

    dnsfilter();
    dnsfilter(const dnsfilter &) = delete;
    dnsfilter(dnsfilter &&) = delete;

    ~dnsfilter();

    dnsfilter &operator=(const dnsfilter &) = delete;
    dnsfilter &operator=(dnsfilter &&) = delete;

    /**
     * @brief      Create filtering engine handle
     * @param[in]  p     engine parameters
     * @return     Engine handle, or nullopt in case of fatal error
     */
    std::optional<handle> create(engine_params p);

    /**
     * @brief      Destroy filtering engine handle
     * @param[in]  obj   handle
     */
    void destroy(handle obj);

    /**
     * @brief      Match domain against added rules
     * @param[in]  obj     filtering engine handle
     * @param[in]  domain  domain to be matched
     * @return     List of matched rules (please note, that it contains all matched rules
     *             in undefined order, so the one should use `get_effective_rule` to get
     *             the rule, which should be considered in request blocking logic)
     */
    std::vector<rule> match(handle obj, std::string_view domain);

    /**
     * @brief      Select the rule which should be applied to the request
     * @param[in]  rules  matched rules
     * @return     Selected rule (may be null, which should be considered as none matched)
     */
    static const dnsfilter::rule *get_effective_rule(const std::vector<rule> &rules);
};

} // namespace ag
