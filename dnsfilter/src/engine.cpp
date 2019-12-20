#include <algorithm>
#include <dnsfilter.h>
#include <ag_logger.h>
#include "filter.h"
#include "rule_utils.h"


using namespace ag;

class engine {
public:
    engine(dnsfilter::engine_params p)
        : log(ag::create_logger("dnsfilter"))
    {
        this->filters.reserve(p.filters.size());
        for (size_t i = 0; i < p.filters.size(); ++i) {
            filter f = {};
            if (0 == f.load(p.filters[i])) {
                this->filters.emplace_back(std::move(f));
                infolog(log, "Filter added successfully: {}", p.filters[i].path);
            } else {
                warnlog(log, "Filter was not added: {}", p.filters[i].path);
            }
        }
        this->filters.shrink_to_fit();
    }

    ~engine() {}

    ag::logger log;
    std::vector<filter> filters;
};


dnsfilter::dnsfilter() = default;

dnsfilter::~dnsfilter() = default;

std::optional<dnsfilter::handle> dnsfilter::create(engine_params p) {
    engine *e = new(std::nothrow) engine(std::move(p));
    if (e == nullptr) {
        SPDLOG_ERROR("no memory to create dns filter");
        return std::nullopt;
    }

    return std::make_optional(e);
}

void dnsfilter::destroy(handle obj) {
    engine *e = (engine *)obj;
    delete e;
}

std::vector<dnsfilter::rule> dnsfilter::match(handle obj, std::string_view domain) {
    engine *e = (engine *)obj;

    tracelog(e->log, "Matching {}", domain);

    filter::match_context context = filter::create_match_context(domain);

    for (filter &f : e->filters) {
        f.match(context);
    }

    tracelog(e->log, "Matched {} rules", context.matched_rules.size());

    return context.matched_rules;
}

static bool has_higher_priority(const dnsfilter::rule &l, const dnsfilter::rule &r) {
    // in ascending order (the higher index, the higher priority)
    static constexpr std::bitset<dnsfilter::RP_NUM> PRIORITY_TABLE[] = {
        {},
        { (1 << dnsfilter::RP_EXCEPTION) },
        { (1 << dnsfilter::RP_IMPORTANT) },
        { (1 << dnsfilter::RP_IMPORTANT) | (1 << dnsfilter::RP_EXCEPTION) },
    };

    for (const std::bitset<dnsfilter::RP_NUM> &p : PRIORITY_TABLE) {
        if ((l.props == p) != (r.props == p)) {
            return l.props == p;
        }
    }
    // a rule with hosts file syntax has higher priority
    return !l.ip.has_value() && r.ip.has_value();
}

std::vector<const dnsfilter::rule *> dnsfilter::get_effective_rules(const std::vector<rule> &rules) {
    const rule *effective_rules[rules.size()];
    size_t effective_rules_num = 0;
    const rule *badfilter_rules[rules.size()];
    size_t badfilter_rules_num = 0;

    for (const rule &r : rules) {
        if (!r.props.test(RP_BADFILTER)) {
            effective_rules[effective_rules_num++] = &r;
        } else {
            badfilter_rules[badfilter_rules_num++] = &r;
        }
    }

    std::stable_sort(effective_rules, effective_rules + effective_rules_num,
        [] (const rule *l, const rule *r) { return !has_higher_priority(*l, *r); });

    std::string badfilter_rule_texts[badfilter_rules_num];
    for (size_t i = 0; i < badfilter_rules_num; ++i) {
        const rule *r = badfilter_rules[i];
        badfilter_rule_texts[i] = rule_utils::get_text_without_badfilter(*r);
    }

    std::string *badfilter_rules_end = badfilter_rule_texts + badfilter_rules_num;
    size_t i;
    for (i = 0; i < effective_rules_num; ++i) {
        const rule *r = effective_rules[i];
        const std::string *found = std::find(badfilter_rule_texts, badfilter_rules_end, r->text);
        if (found == badfilter_rules_end) {
            if (!r->ip.has_value()) {
                // faced with some more important rule than the one with hosts file syntax
                // or there are no such rules in the list
                return { r };
            } else {
                break;
            }
        }
    }

    // there are no suitable rules at all
    if (i >= effective_rules_num) {
        return {};
    }

    // if we got here, there should be some number of the rules with hosts file syntax, which are
    // needed to be extracted
    size_t seek = i;
    while (seek < effective_rules_num && effective_rules[seek]->ip.has_value()) {
        ++seek;
    }
    assert(seek > i);

    std::vector<const rule *> result;
    result.reserve(seek - i);
    for (; i < seek; ++i) {
        result.emplace_back(effective_rules[i]);
    }
    return result;
}

bool dnsfilter::is_valid_rule(std::string_view str) {
    return rule_utils::parse(str).has_value();
}
