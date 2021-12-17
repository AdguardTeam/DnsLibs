#include <algorithm>
#include <dnsfilter.h>
#include "common/logger.h"
#include "common/file.h"
#include "filter.h"
#include "rule_utils.h"
#include "common/utils.h"
#include <unordered_set>
#include <atomic>
using namespace ag;

class engine {
public:
    engine() : log("dnsfilter") {}

    ~engine() = default;

    /**
     * @return {true, optional warning} or {false, error description}
     */
    std::pair<bool, ErrString> init(const dnsfilter::engine_params &p) {
        mem_limit = p.mem_limit;
        std::string warnings;
        std::unordered_set<uint32_t> ids;

        this->filters.reserve(p.filters.size());
        for (const dnsfilter::filter_params &fp : p.filters) {
            filter f = {};
            auto [res, f_mem] = f.load(fp, mem_limit);
            mem_limit -= f_mem;
            if (res == filter::LR_OK) {
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

    /**
     * Update file filters
     */
    void update_filters(std::vector<filter *> &f) {
        std::unique_lock write_lock(filters_mtx);
        for (auto *filter : f) {
            filter->update(mem_limit);
        }
    }

    std::atomic_size_t mem_limit;
    ag::Logger log;
    std::vector<filter> filters;
    std::shared_mutex filters_mtx;
};

/**
* Match domain against added rules. Return vector of outdated filters.
* @param obj    filtering engine handle
* @param param  see `match_param`
* @return       vector of pointer to the outdated filters
*/
static std::vector<filter *> inner_match(dnsfilter::handle obj, dnsfilter::match_param param, filter::match_context &context) {
    engine *e = (engine *)obj;

    std::shared_lock read_lock(e->filters_mtx);
    std::vector<filter *> outdated_filters;

    for (filter &f : e->filters) {
        if (!f.match(context)) {
            outdated_filters.push_back(&f);
        }
    }
    return outdated_filters;
}

/**
 * Match domain against with vector of filters
 * @param obj              filtering engine handle
 * @param param            see `match_param`
 * @param context          context of domain match
 * @param outdated_filters vector of pointer to the outdated filters
 */
static void inner_match_outdated(dnsfilter::handle obj, dnsfilter::match_param param,
                          filter::match_context &context, std::vector<filter *> &outdated_filters) {
    engine *e = (engine *)obj;
    std::shared_lock read_lock(e->filters_mtx);

    for (filter *f : outdated_filters) {
        if (!f->match(context)) {
            warnlog(e->log, "Filter {} outdated immediately after update", f->params.id);
        }
    }
    outdated_filters.clear();
}

dnsfilter::dnsfilter() = default;

dnsfilter::~dnsfilter() = default;

std::pair<dnsfilter::handle, ErrString> dnsfilter::create(const engine_params &p) {
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

std::vector<dnsfilter::rule> dnsfilter::match(handle obj, match_param param) {
    engine *e = (engine *)obj;

    tracelog(e->log, "Matching {}", param.domain);

    filter::match_context context = filter::create_match_context(param);

    auto outdated_filters = inner_match(obj, param, context);

    if (!outdated_filters.empty()) {
        e->update_filters(outdated_filters);
        inner_match_outdated(obj, param, context, outdated_filters);
    }

    if (!context.reverse_lookup_fqdn.empty()) {
        context.host = std::move(context.reverse_lookup_fqdn);
        context.subdomains = { context.host };

        outdated_filters = inner_match(obj, param, context);

        if (!outdated_filters.empty()) {
            e->update_filters(outdated_filters);
            inner_match_outdated(obj, param, context, outdated_filters);
        }
    }

    tracelog(e->log, "Matched {} rules", context.matched_rules.size());

    return std::move(context.matched_rules);
}

// Return true if the left rule prevails over the right one
static bool has_higher_priority(const dnsfilter::rule *l, const dnsfilter::rule *r) {
    using props_set = dnsfilter::adblock_rule_info::props_set;

    // in ascending order (the higher index, the higher priority)
    static constexpr props_set PRIORITY_TABLE[] = {
        {},
        { (1 << dnsfilter::DARP_EXCEPTION) },
        { (1 << dnsfilter::DARP_IMPORTANT) },
        { (1 << dnsfilter::DARP_IMPORTANT) | (1 << dnsfilter::DARP_EXCEPTION) },
    };

    auto get_rule_props =
            [] (const dnsfilter::rule *rule) -> props_set {
                if (const auto *c = std::get_if<dnsfilter::adblock_rule_info>(&rule->content); c != nullptr) {
                    return c->props;
                }
                return {};
            };

    props_set lprops = get_rule_props(l);
    props_set rprops = get_rule_props(r);

    if (lprops != rprops) {
        size_t lpriority = 0;
        size_t rpriority = 0;
        for (size_t i = 1; i < std::size(PRIORITY_TABLE); ++i) {
            const props_set &props = PRIORITY_TABLE[i];
            if ((lprops & props) == props) {
                lpriority = i;
            }
            if ((rprops & props) == props) {
                rpriority = i;
            }
        }
        if (lpriority != rpriority) {
            return lpriority > rpriority;
        }
    }

    // a rule with hosts file syntax has higher priority
    return std::get_if<dnsfilter::etc_hosts_rule_info>(&l->content) != nullptr
            && std::get_if<dnsfilter::etc_hosts_rule_info>(&r->content) == nullptr;
}

static std::vector<const dnsfilter::rule *> filter_out_by_badfilter(const std::vector<dnsfilter::rule> &rules) {
    const dnsfilter::rule *rule_ptrs[rules.size()];
    std::transform(rules.begin(), rules.end(), rule_ptrs,
            [] (const dnsfilter::rule &r) { return &r; });

    auto badfilter_rules_start = std::partition(rule_ptrs, rule_ptrs + rules.size(),
            [] (const dnsfilter::rule *r) {
                const auto *info = std::get_if<dnsfilter::adblock_rule_info>(&r->content);
                return info == nullptr || !info->props.test(dnsfilter::DARP_BADFILTER);
            });

    std::string badfilter_texts[std::distance(badfilter_rules_start, rule_ptrs + rules.size())];
    std::string *badfilter_texts_end =
            badfilter_texts + std::distance(badfilter_rules_start, rule_ptrs + rules.size());
    std::transform(badfilter_rules_start, rule_ptrs + rules.size(), badfilter_texts,
            [] (const dnsfilter::rule *r) { return rule_utils::get_text_without_badfilter(*r); });

    std::vector<const dnsfilter::rule *> result;
    result.reserve(std::distance(rule_ptrs, badfilter_rules_start));
    for (size_t i = 0; i < (size_t)std::distance(rule_ptrs, badfilter_rules_start); ++i) {
        const dnsfilter::rule *r = rule_ptrs[i];

        const std::string *found = std::find(badfilter_texts, badfilter_texts_end, r->text);
        if (found == badfilter_texts_end) {
            result.push_back(r);
        }
    }

    return result;
}

static dnsfilter::effective_rules categorize_rules(const std::vector<const dnsfilter::rule *> &rules) {
    dnsfilter::effective_rules result;
    for (const dnsfilter::rule *r : rules) {
        if (const auto *info = std::get_if<dnsfilter::adblock_rule_info>(&r->content);
                info != nullptr && info->props.test(dnsfilter::DARP_DNSREWRITE)) {
            result.dnsrewrite.push_back(r);
        } else {
            result.leftovers.push_back(r);
        }
    }
    return result;
}

dnsfilter::effective_rules dnsfilter::get_effective_rules(const std::vector<rule> &rules) {
    std::vector<const rule *> good_rules = filter_out_by_badfilter(rules);
    effective_rules effective_rules = categorize_rules(good_rules);
    if (effective_rules.leftovers.empty()) {
        return effective_rules;
    }

    // no need to sort $dnsrewrite's as they handled specially
    std::sort(effective_rules.leftovers.begin(), effective_rules.leftovers.end(), has_higher_priority);

    if (const auto *info = std::get_if<adblock_rule_info>(&effective_rules.leftovers[0]->content);
            info != nullptr && !info->props.test(DARP_EXCEPTION)) {
        // return only the first blocking adblock-style rule
        effective_rules.leftovers.resize(1);
    } else {
        // return all exceptions or hosts-file-syntax rules
        auto last = std::adjacent_find(effective_rules.leftovers.begin(), effective_rules.leftovers.end(),
                has_higher_priority);
        if (last != effective_rules.leftovers.end()) {
            last = std::next(last);
        }
        effective_rules.leftovers.resize(std::distance(effective_rules.leftovers.begin(), last));
    }

    return effective_rules;
}

bool dnsfilter::is_valid_rule(std::string_view str) {
    return rule_utils::parse(str).has_value();
}
