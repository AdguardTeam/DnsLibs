#include <algorithm>

#include "rule_utils.h"

namespace ag::dns::dnsfilter {

static constexpr std::string_view DOMAINS_DELIMITER = "|";

bool rule_utils::parse_denyallow_modifier(
        Rule &rule, std::string_view params_str, const MatchInfo &match_info, Logger *log) {
    if (ag::utils::trim(params_str).empty()) {
        dbglog(*log, "The denyallow modifier requires a list of domains as a parameter");
        return false;
    }
    auto &content = std::get<DnsFilter::AdblockRuleInfo>(rule.public_part.content);
    std::vector<std::string_view> domains = ag::utils::split_by(params_str, DOMAINS_DELIMITER);
    content.params->denyallow_domains.reserve(domains.size());
    std::transform(domains.begin(), domains.end(), std::back_inserter(content.params->denyallow_domains),
            [](std::string_view domain) {
                return std::string(domain);
            });
    return true;
}

} // namespace ag::dns::dnsfilter
