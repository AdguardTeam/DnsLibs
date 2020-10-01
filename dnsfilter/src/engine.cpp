#include <algorithm>
#include <dnsfilter.h>
#include <ag_logger.h>
#include "filter.h"
#include "rule_utils.h"
#include <ag_utils.h>
#include <unordered_set>

using namespace ag;

class engine {
public:
    engine() : log(ag::create_logger("dnsfilter")) {}

    ~engine() = default;

    /**
     * @return {true, optional warning} or {false, error description}
     */
    std::pair<bool, err_string> init(const dnsfilter::engine_params &p) {
        size_t mem_limit = p.mem_limit;
        std::string warnings;
        std::unordered_set<uint32_t> ids;

        this->filters.reserve(p.filters.size());
        for (const dnsfilter::filter_params &fp : p.filters) {
            filter f = {};
            auto [res, f_mem] = f.load(fp, mem_limit);
            if (res == filter::LR_OK) {
                mem_limit -= f_mem;
                this->filters.emplace_back(std::move(f));
                infolog(log, "Filter {} added successfully", fp.id);
            } else if (res == filter::LR_ERROR) {
                auto err = AG_FMT("Filter {} was not added because of an error", fp.id);
                errlog(log, "{}", err);
                filters.clear();
                return {false, std::move(err)};
            } else if (res == filter::LR_MEM_LIMIT_REACHED) {
                warnings += AG_FMT("Filter {} added partially (reached memory limit)\n", fp.id);
                break;
            }
            if (ids.count(fp.id)) {
                warnings += AG_FMT("Non unique filter id: {}, data: {}\n", fp.id, fp.data);
            }
            ids.insert(fp.id);
        }
        this->filters.shrink_to_fit();
        if (!warnings.empty()) {
            warnlog(log, "Filters loaded with warnings:\n{}", warnings);
            return {true, std::move(warnings)};
        }
        return {true, std::nullopt};
    }

    ag::logger log;
    std::vector<filter> filters;
};


dnsfilter::dnsfilter() = default;

dnsfilter::~dnsfilter() = default;

std::pair<dnsfilter::handle, err_string> dnsfilter::create(const engine_params &p) {
    auto *e = new(std::nothrow) engine();
    if (!e) {
        return {nullptr, "No memory for the filtering engine"};
    }
    auto [ret, err_or_warn] = e->init(p);
    if (!ret) {
        delete e;
        return {nullptr, std::move(err_or_warn)};
    }
    return {e, std::move(err_or_warn)};
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
