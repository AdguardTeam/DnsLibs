#pragma once


#include <string_view>
#include <memory>
#include <vector>
#include <dnsfilter.h>
#include "rule_utils.h"

class filter {
public:
    // Context of domain match
    struct match_context {
        std::string host; // matching domain name
        std::vector<std::string_view> subdomains; // list of subdomains
        std::vector<ag::dnsfilter::rule> matched_rules; // list of matched rules
    };

    static match_context create_match_context(std::string_view host);

    filter();
    ~filter();

    filter(filter&&);
    filter &operator=(filter&&);

    filter(const filter&) = delete;
    filter &operator=(const filter&) = delete;

    /**
     * Load rule list
     * @param[in]  params  filter parameters
     * @return     >= 0 if loaded successfully
     *             <0 otherwise
     */
    int load(const ag::dnsfilter::filter_params &params);

    /**
     * Match domain against rules
     * @param      ctx   match context
     */
    void match(match_context &ctx);

    // Filter parameters
    ag::dnsfilter::filter_params params;

private:
    class impl;
    std::unique_ptr<impl> pimpl;
};
