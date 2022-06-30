#include "common/file.h"
#include "common/logger.h"
#include "common/utils.h"
#include "dnsfilter/dnsfilter.h"
#include "filter.h"
#include "rule_utils.h"
#include <algorithm>
#include <atomic>
#include <unordered_set>

namespace ag::dnsfilter {

class Engine {
public:
    Engine()
            : m_log("dnsfilter") {
    }

    ~Engine() = default;

    /**
     * @return {true, optional warning} or {false, error description}
     */
    std::pair<bool, ErrString> init(const DnsFilter::EngineParams &p) {
        m_mem_limit = p.mem_limit;
        std::string warnings;
        std::unordered_set<uint32_t> ids;

        m_filters.reserve(p.filters.size());
        for (const DnsFilter::FilterParams &fp : p.filters) {
            Filter f = {};
            auto [res, f_mem] = f.load(fp, m_mem_limit);
            m_mem_limit -= f_mem;
            if (res == Filter::LR_OK) {
                m_filters.emplace_back(std::move(f));
                infolog(m_log, "Filter {} added successfully", fp.id);
            } else if (res == Filter::LR_ERROR) {
                auto err = AG_FMT("Filter {} was not added because of an error", fp.id);
                errlog(m_log, "{}", err);
                m_filters.clear();
                return {false, std::move(err)};
            } else if (res == Filter::LR_MEM_LIMIT_REACHED) {
                warnings += AG_FMT("Filter {} added partially (reached memory limit)\n", fp.id);
                break;
            }
            if (ids.count(fp.id)) {
                warnings += AG_FMT("Non unique filter id: {}, data: {}\n", fp.id, fp.data);
            }
            ids.insert(fp.id);
        }
        m_filters.shrink_to_fit();
        if (!warnings.empty()) {
            warnlog(m_log, "Filters loaded with warnings:\n{}", warnings);
            return {true, std::move(warnings)};
        }
        return {true, std::nullopt};
    }

    /**
     * Update file filters
     */
    void update_filters(std::vector<Filter *> &filters) {
        std::unique_lock write_lock(m_filters_mtx);
        for (auto *filter : filters) {
            filter->update(m_mem_limit);
        }
    }

    std::atomic_size_t m_mem_limit;
    ag::Logger m_log;
    std::vector<Filter> m_filters;
    std::shared_mutex m_filters_mtx;
};

/**
 * Match domain against added rules. Return vector of outdated filters.
 * @param obj    filtering engine handle
 * @param param  see `match_param`
 * @return       vector of pointer to the outdated filters
 */
static std::vector<Filter *> inner_match(
        DnsFilter::Handle obj, DnsFilter::MatchParam param, Filter::MatchContext &context) {
    Engine *e = (Engine *) obj;

    std::shared_lock read_lock(e->m_filters_mtx);
    std::vector<Filter *> outdated_filters;

    for (Filter &f : e->m_filters) {
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
static void inner_match_outdated(DnsFilter::Handle obj, DnsFilter::MatchParam param, Filter::MatchContext &context,
        std::vector<Filter *> &outdated_filters) {
    Engine *e = (Engine *) obj;
    std::shared_lock read_lock(e->m_filters_mtx);

    for (Filter *f : outdated_filters) {
        if (!f->match(context)) {
            warnlog(e->m_log, "Filter {} outdated immediately after update", f->params.id);
        }
    }
    outdated_filters.clear();
}

} // namespace ag::dnsfilter

namespace ag {

DnsFilter::DnsFilter() = default;

DnsFilter::~DnsFilter() = default;

std::pair<DnsFilter::Handle, ErrString> DnsFilter::create(const EngineParams &p) {
    auto *e = new (std::nothrow) dnsfilter::Engine();
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

void DnsFilter::destroy(Handle obj) {
    dnsfilter::Engine *e = (dnsfilter::Engine *) obj;
    delete e;
}

std::vector<DnsFilter::Rule> DnsFilter::match(Handle obj, MatchParam param) {
    dnsfilter::Engine *e = (dnsfilter::Engine *) obj;

    tracelog(e->m_log, "Matching {}", param.domain);

    dnsfilter::Filter::MatchContext context{};
    dnsfilter::Filter::init_match_context(context, param);

    auto outdated_filters = inner_match(obj, param, context);

    if (!outdated_filters.empty()) {
        e->update_filters(outdated_filters);
        inner_match_outdated(obj, param, context, outdated_filters);
    }

    if (!context.reverse_lookup_fqdn.empty()) {
        context.host = std::move(context.reverse_lookup_fqdn);
        context.subdomains = {context.host};

        outdated_filters = inner_match(obj, param, context);

        if (!outdated_filters.empty()) {
            e->update_filters(outdated_filters);
            inner_match_outdated(obj, param, context, outdated_filters);
        }
    }

    tracelog(e->m_log, "Matched {} rules", context.matched_rules.size());

    return std::move(context.matched_rules);
}

// Return true if the left rule prevails over the right one
static bool has_higher_priority(const DnsFilter::Rule *l, const DnsFilter::Rule *r) {
    using PropsSet = DnsFilter::AdblockRuleInfo::PropsSet;

    // in ascending order (the higher index, the higher priority)
    static constexpr PropsSet PRIORITY_TABLE[] = {
            {},
            {(1 << DnsFilter::DARP_EXCEPTION)},
            {(1 << DnsFilter::DARP_IMPORTANT)},
            {(1 << DnsFilter::DARP_IMPORTANT) | (1 << DnsFilter::DARP_EXCEPTION)},
    };

    auto get_rule_props = [](const DnsFilter::Rule *rule) -> PropsSet {
        if (const auto *c = std::get_if<DnsFilter::AdblockRuleInfo>(&rule->content); c != nullptr) {
            return c->props;
        }
        return {};
    };

    PropsSet lprops = get_rule_props(l);
    PropsSet rprops = get_rule_props(r);

    if (lprops != rprops) {
        size_t lpriority = 0;
        size_t rpriority = 0;
        for (size_t i = 1; i < std::size(PRIORITY_TABLE); ++i) {
            const PropsSet &props = PRIORITY_TABLE[i];
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
    return std::get_if<DnsFilter::HostsRuleInfo>(&l->content) != nullptr
            && std::get_if<DnsFilter::HostsRuleInfo>(&r->content) == nullptr;
}

static std::vector<const DnsFilter::Rule *> filter_out_by_badfilter(const std::vector<DnsFilter::Rule> &rules) {
    const DnsFilter::Rule *rule_ptrs[rules.size()];
    std::transform(rules.begin(), rules.end(), rule_ptrs, [](const DnsFilter::Rule &r) {
        return &r;
    });

    auto badfilter_rules_start = std::partition(rule_ptrs, rule_ptrs + rules.size(), [](const DnsFilter::Rule *r) {
        const auto *info = std::get_if<DnsFilter::AdblockRuleInfo>(&r->content);
        return info == nullptr || !info->props.test(DnsFilter::DARP_BADFILTER);
    });

    std::string badfilter_texts[std::distance(badfilter_rules_start, rule_ptrs + rules.size())];
    std::string *badfilter_texts_end = badfilter_texts + std::distance(badfilter_rules_start, rule_ptrs + rules.size());
    std::transform(badfilter_rules_start, rule_ptrs + rules.size(), badfilter_texts, [](const DnsFilter::Rule *r) {
        return dnsfilter::rule_utils::get_text_without_badfilter(*r);
    });

    std::vector<const DnsFilter::Rule *> result;
    result.reserve(std::distance(rule_ptrs, badfilter_rules_start));
    for (size_t i = 0; i < (size_t) std::distance(rule_ptrs, badfilter_rules_start); ++i) {
        const DnsFilter::Rule *r = rule_ptrs[i];

        const std::string *found = std::find(badfilter_texts, badfilter_texts_end, r->text);
        if (found == badfilter_texts_end) {
            result.push_back(r);
        }
    }

    return result;
}

static DnsFilter::effective_rules categorize_rules(const std::vector<const DnsFilter::Rule *> &rules) {
    DnsFilter::effective_rules result;
    for (const DnsFilter::Rule *r : rules) {
        if (const auto *info = std::get_if<DnsFilter::AdblockRuleInfo>(&r->content);
                info != nullptr && info->props.test(DnsFilter::DARP_DNSREWRITE)) {
            result.dnsrewrite.push_back(r);
        } else {
            result.leftovers.push_back(r);
        }
    }
    return result;
}

DnsFilter::effective_rules DnsFilter::get_effective_rules(const std::vector<Rule> &rules) {
    std::vector<const Rule *> good_rules = filter_out_by_badfilter(rules);
    effective_rules effective_rules = categorize_rules(good_rules);
    if (effective_rules.leftovers.empty()) {
        return effective_rules;
    }

    // no need to sort $dnsrewrite's as they handled specially
    std::sort(effective_rules.leftovers.begin(), effective_rules.leftovers.end(), has_higher_priority);

    if (const auto *info = std::get_if<AdblockRuleInfo>(&effective_rules.leftovers[0]->content);
            info != nullptr && !info->props.test(DARP_EXCEPTION)) {
        // return only the first blocking adblock-style rule
        effective_rules.leftovers.resize(1);
    } else {
        // return all exceptions or hosts-file-syntax rules
        auto last = std::adjacent_find(
                effective_rules.leftovers.begin(), effective_rules.leftovers.end(), has_higher_priority);
        if (last != effective_rules.leftovers.end()) {
            last = std::next(last);
        }
        effective_rules.leftovers.resize(std::distance(effective_rules.leftovers.begin(), last));
    }

    return effective_rules;
}

} // namespace ag
