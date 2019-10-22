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
                infolog(log, "filter added successfully: {}", p.filters[i].path);
            } else {
                warnlog(log, "filter was not added: {}", p.filters[i].path);
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

    dbglog(e->log, "matching {}", domain);

    filter::match_context context = filter::create_match_context(domain);

    for (filter &f : e->filters) {
        f.match(context);
    }

    dbglog(e->log, "matched {} rules", context.matched_rules.size());

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
    return false;
}

const dnsfilter::rule *dnsfilter::get_effective_rule(const std::vector<rule> &rules) {
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

    for (size_t i = 0; i < effective_rules_num; ++i) {
        const rule *r = effective_rules[i];
        const std::string *found = std::find(badfilter_rule_texts,
            badfilter_rule_texts + badfilter_rules_num, r->text);
        if (found == badfilter_rule_texts + badfilter_rules_num) {
            return r;
        }
    }

    return nullptr;
}
