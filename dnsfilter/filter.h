#pragma once

#include <atomic>
#include <memory>
#include <optional>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <vector>

#include "dns/dnsfilter/dnsfilter.h"
#include "rule_utils.h"

namespace ag::dns::dnsfilter {

class Filter {
public:
    // Context of domain match
    struct MatchContext {
        explicit MatchContext(DnsFilter::MatchParam param);

        MatchContext(const MatchContext &) = delete;
        MatchContext &operator=(const MatchContext &) = delete;
        MatchContext(MatchContext &&) = delete;
        MatchContext &operator=(MatchContext &&) = delete;

        std::string host; // matching domain name
        std::vector<std::string_view> subdomains; // list of subdomains
        std::vector<DnsFilter::Rule> matched_rules; // list of matched rules
        ldns_rr_type rr_type; // query RR type
        std::string reverse_lookup_fqdn; // non-empty if the request is a reverse DNS lookup
        std::optional<CidrRange> ip_as_cidr; // non-nullopt in case the `host` is an IP address
    };

    [[nodiscard]] static MatchContext make_match_context(DnsFilter::MatchParam param);

    Filter();
    ~Filter();

    Filter(Filter&&);
    Filter &operator=(Filter&&);

    Filter(const Filter&) = delete;
    Filter &operator=(const Filter&) = delete;

    enum LoadResult {
        LR_OK, LR_ERROR, LR_MEM_LIMIT_REACHED
    };

    /**
     * Load rule list
     * @param      params    filter parameters
     * @param      mem_limit if not 0, stop loading rules when the approximate memory consumption reaches this limit
     * @return     {load_result, approximate memory consumption}
     */
    std::pair<LoadResult, size_t> load(const DnsFilter::FilterParams &params, size_t mem_limit);

    /**
     * Match domain against rules
     * @param      ctx   match context
     * @return     true if match success, false if filter is outdated
     */
    bool match(MatchContext &ctx);

    /**
     * Update filter
     * @param   mem_limit    engine memory limit
     */
    void update(std::atomic_size_t &mem_limit);

    // Filter parameters
    DnsFilter::FilterParams params;

private:
    class Impl;
    std::unique_ptr<Impl> m_pimpl;
};

} // namespace ag::dns::dnsfilter
