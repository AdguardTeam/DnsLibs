#pragma once


#include <string_view>
#include <ag_logger.h>
#include <dnsfilter.h>


/**
 *  Set of helper functions to manage the rules
 *  Useful links:
 *   - https://github.com/AdguardTeam/AdguardHome/wiki/Hosts-Blocklists
 */
namespace rule_utils {

    struct rule {
        enum match_method_id {
            MMID_DOMAINS, // a domain can be matched against such rule by comparing
                          // with items of `matching_parts`, if it's equal to any it's matched
            MMID_SHORTCUTS, // a domain can be matched against such rule, if it contains each item
                            // of `matching_parts` in corresponding order
                            // (e.g. `example*.org` -> { `example`, `.org` })
            MMID_REGEX, // a domain can be matched against such rule only by applying the regex
            MMID_SHORTCUTS_AND_REGEX, // an optimized version of `MMID_REGEX` (as regex applying
                                      // is pretty expensive operation): if it's possible
                                      // some shortcuts will be extracted from a rule (e.g.
                                      // `/exampl.*\.com/` -> { `exampl`, `.com` }), and if a domain
                                      // contains these shortcuts in corresponding order and matches
                                      // the regex, it is matched against the rule
        };

        // public part of rule structure (see `ag::dnsfilter::rule`)
        ag::dnsfilter::rule public_part;
        // see `match_method_id`
        match_method_id match_method;
        // list of matching parts accordingly to `match_method` value
        std::vector<std::string> matching_parts;
    };


    /**
     * @brief      Check if string is a commentary
     */
    static inline bool is_comment(std::string_view str) {
        return str[0] == '!' || str[0] == '#';
    }

    /**
     * @brief      Parse rule from given string
     * @param[in]  str   input string
     * @param[in]  log   logger (if null, rule parsing errors won't be logged)
     * @return     A rule if parsed successfully,
     *             nullopt otherwise
     */
    std::optional<rule> parse(std::string_view str, ag::logger *log = nullptr);

    /**
     * @brief      Extract a regular expression text from rule
     * @param[in]  r     rule
     * @return     Regular expression text
     */
    std::string get_regex(const rule &r);

    /**
     * @brief      Generate the rule text without badfilter modifier
     * @param[in]  r     rule
     * @return     Text without badfilter modifier
     */
    std::string get_text_without_badfilter(const ag::dnsfilter::rule &r);

} // namespace rule_utils
