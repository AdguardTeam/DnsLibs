#include "dns/dnsfilter/dnsfilter.h"

#include <string_view>

#include "common/utils.h"
#include "tldregistry/tldregistry.h"

#include "rule_utils.h"

ag::dns::DnsFilter::RuleTemplate::RuleTemplate(std::string text)
        : text{std::move(text)} {
}

std::optional<ag::dns::DnsFilter::FilteringLogAction> ag::dns::DnsFilter::suggest_action(
        const ag::dns::DnsRequestProcessedEvent &event) {
    if (event.domain.empty()) {
        return std::nullopt;
    }

    std::optional<ag::dns::dnsfilter::rule_utils::Rule> rule;
    AdblockRuleInfo *info = nullptr;

    if (!event.rules.empty()) {
        rule = ag::dns::dnsfilter::rule_utils::parse(event.rules.front());
        if (!rule) {
            return std::nullopt;
        }
        info = std::get_if<AdblockRuleInfo>(&rule->public_part.content);
    }

    FilteringLogAction action;
    action.allowed_options = RGO_IMPORTANT;
    if (!event.type.empty()) {
        action.allowed_options |= RGO_DNSTYPE;
    }
    action.blocking = !rule || (info && info->props.test(DARP_EXCEPTION));

    if (info && info->props.test(DARP_IMPORTANT)) {
        if (info->props.test(DARP_EXCEPTION)) {
            action.allowed_options = action.required_options = 0;
            action.templates.emplace_back(AG_FMT("{},badfilter", rule->public_part.text));
            return action;
        }
        action.required_options |= RGO_IMPORTANT;
    }

    std::string_view normalized_domain = dnsfilter::rule_utils::normalize_domain_dot(event.domain);
    action.templates.emplace_back(AG_FMT("{}||{}^", action.blocking ? "" : "@@", normalized_domain));

    if (std::string_view reduced_domain = tldregistry::reduce_domain(event.domain, 1); reduced_domain != normalized_domain) {
        action.templates.emplace_back(AG_FMT("{}||{}^", action.blocking ? "" : "@@", reduced_domain));
    }

    return action;
}

std::string ag::dns::DnsFilter::generate_rule(
        const RuleTemplate &rule_template, const DnsRequestProcessedEvent &event, uint32_t options) {
    std::string modifiers;

    if ((options & RGO_DNSTYPE) && !event.type.empty()) {
        modifiers += ",dnstype=";
        modifiers += event.type;
    }

    if (options & RGO_IMPORTANT) {
        modifiers += ",important";
    }

    if (!modifiers.empty()) {
        modifiers.front() = '$';
    }

    return AG_FMT("{}{}", rule_template.text, modifiers);
}
