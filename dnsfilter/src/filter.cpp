#include <string_view>
#include <cstdlib>
#include <inttypes.h>
#include <algorithm>
#include <cassert>
#include <tuple>
#include <ag_regex.h>
#include <ag_logger.h>
#include <ag_utils.h>
#include <ag_net_utils.h>
#include <ag_file.h>
#include <ag_sys.h>
#include <dnsfilter.h>
#include <khash.h>
#include "filter.h"
#include "rule_utils.h"


static constexpr size_t SHORTCUT_LENGTH = 5;

KHASH_MAP_INIT_INT(hash_to_unique_index, uint32_t)
KHASH_MAP_INIT_INT(hash_to_indexes, std::vector<uint32_t>*)


struct match_arg {
    filter::match_context &ctx;
    filter &f;
    ag::file::handle file;
};


static void destroy_unique_index_table(kh_hash_to_unique_index_t *table) {
    if (table != nullptr) {
        for (khiter_t i = kh_begin(table); i != kh_end(table); ++i) {
            if (kh_exist(table, i)) {
                kh_del(hash_to_unique_index, table, i);
            }
        }
        kh_destroy(hash_to_unique_index, table);
    }
}

static void destroy_multi_index_table(kh_hash_to_indexes_t *table) {
    if (table != nullptr) {
        for (khiter_t i = kh_begin(table); i != kh_end(table); ++i) {
            if (kh_exist(table, i)) {
                delete kh_value(table, i);
                kh_del(hash_to_indexes, table, i);
            }
        }
        kh_destroy(hash_to_indexes, table);
    }
}


class filter::impl {
public:
    impl()
        : unique_domains_table(kh_init(hash_to_unique_index))
        , domains_table(kh_init(hash_to_indexes))
        , shortcuts_table(kh_init(hash_to_indexes))
        , badfilter_table(kh_init(hash_to_unique_index))
    {}

    ~impl() {
        destroy_unique_index_table(this->unique_domains_table);
        destroy_multi_index_table(this->domains_table);
        destroy_multi_index_table(this->shortcuts_table);
        destroy_unique_index_table(this->badfilter_table);
    }

    void put_hash_into_tables(uint32_t hash, uint32_t file_idx,
                              kh_hash_to_unique_index_t *unique_table, kh_hash_to_indexes_t *multi_table);
    void process_string(std::string_view str, uint32_t file_idx);

    static bool load_line(uint32_t file_idx, std::string_view line, void *arg);
    static bool match_against_line(match_arg &match, std::string_view line);
    static void match_by_file_position(match_arg &match, size_t idx);

    void search_by_domains(match_arg &match) const;
    void search_by_shortcuts(match_arg &match) const;
    void search_in_leftovers(match_arg &match) const;
    void search_badfilter_rules(match_arg &match) const;

    ag::logger log;

    // unique domain -> rule string file index
    // This table contains indexes of the rules that match exact domains (and their subdomains)
    // (e.g. `example.org`, but for example not `example.org|` or `example.org^` as they
    // match `eeexample.org` as well)
    // As the lion's share of rule domains are unique, using a separate table
    // for such domains saves a lot of memory
    kh_hash_to_unique_index_t *unique_domains_table;
    // non-unique domain -> list of rule string file indexes
    // Similar to the previous one, but contains lists of indexes if the rules that match
    // the same domain.
    kh_hash_to_indexes_t *domains_table;

    // shortcut -> rule string file index
    // Contains indexes of the rules that can be filtered out by checking, if matching domain
    // contains any shortcut
    kh_hash_to_indexes_t *shortcuts_table;

    struct leftover_entry {
        // @note: each entry must contain either or both of shortcuts and regex
        std::vector<std::string> shortcuts; // list of extracted shortcuts
        std::optional<ag::regex> regex; // compiled regex
        uint32_t file_idx; // file index
    };
    // Contains indexes of the rules that are not fitting to place in domains and shortcuts tables
    // due to they are any of:
    // - a regex rule for which the shortcut at least with length `SHORTCUT_LENGTH` was not found
    //   (e.g. `/ex.*\.com/`)
    // - a rule with special symbol for which the shortcut at least with length `SHORTCUT_LENGTH`
    //   was not found (e.g. `ex*.com`)
    // - a regex rule with some complicated expression (see `rule_utils::parse` for details)
    std::vector<leftover_entry> leftovers_table;

    // rule text -> badfilter rule file index
    // Contains indexes of the badfilter rules that could be found by rule text without
    // `badfilter` modifier
    kh_hash_to_unique_index_t *badfilter_table;
};

filter::filter()
    : pimpl(new impl{})
{}

filter::~filter() = default;

filter::filter(filter &&other) {
    *this = std::move(other);
}

filter &filter::operator=(filter &&other) {
    this->params = std::move(other.params);
    this->pimpl = std::move(other.pimpl);
    return *this;
}

void filter::impl::put_hash_into_tables(uint32_t hash, uint32_t file_idx,
                                        kh_hash_to_unique_index_t *unique_table, kh_hash_to_indexes_t *multi_table) {
    bool already_exists = false;
    size_t stored_idx = 0;

    int ret;
    khiter_t iter = kh_get(hash_to_indexes, multi_table, hash);
    if (iter == kh_end(multi_table)) {
        // there is no such domain in non-unique table
        iter = kh_put(hash_to_unique_index, unique_table, hash, &ret);
        if (ret < 0) {
            errlog(log, "Out of memory");
            return;
        }
        already_exists = ret == 0;
        if (!already_exists) {
            // domain is unique - save index
            kh_value(unique_table, iter) = file_idx;
            return;
        } else {
            // we have one record for this domain - remove from unique table
            stored_idx = kh_value(unique_table, iter);
            kh_del(hash_to_unique_index, unique_table, iter);
        }
    }

    // create record in non-unique table
    iter = kh_put(hash_to_indexes, multi_table, hash, &ret);
    if (ret < 0) {
        errlog(log, "Out of memory");
        return;
    } else if (ret > 0) {
        // the record is a new one
        auto *positions = new(std::nothrow) std::vector<uint32_t>;
        if (positions == nullptr) {
            errlog(log, "Out of memory");
            return;
        }
        kh_value(multi_table, iter) = positions;
    }
    std::vector<uint32_t> *positions = kh_value(multi_table, iter);
    if (already_exists) {
        // put previously stored unique index, if it existed
        positions->reserve(positions->size() + 2);
        positions->push_back(stored_idx);
    }
    positions->push_back(file_idx);
}

void filter::impl::process_string(std::string_view str, uint32_t file_idx) {
    std::optional<rule_utils::rule> rule = rule_utils::parse(str, &log);
    if (!rule.has_value()) {
        if (!str.empty() && !rule_utils::is_comment(str)) {
            warnlog(log, "Failed to parse rule: {}", str);
        }
        return;
    }

    if (rule->public_part.props.test(ag::dnsfilter::RP_BADFILTER)) {
        std::string text = rule_utils::get_text_without_badfilter(rule->public_part);
        uint32_t hash = ag::utils::hash(text);
        int ret;
        khiter_t iter = kh_put(hash_to_unique_index, this->badfilter_table, hash, &ret);
        if (ret < 0) {
            warnlog(log, "Failed to put rule in badfilter table: {}", str);
        } else {
            kh_value(this->badfilter_table, iter) = file_idx;
            tracelog(log, "Rule placed in badfilter table: {}", str);
        }
        return;
    }

    switch (rule->match_method) {
    case rule_utils::rule::MMID_EXACT:
    case rule_utils::rule::MMID_SUBDOMAINS:
        tracelog(log, "Placing a rule in domains table: {}", str);
        for (const std::string &d : rule->matching_parts) {
            put_hash_into_tables(ag::utils::hash(d), file_idx, this->unique_domains_table, this->domains_table);
        }
        break;
    case rule_utils::rule::MMID_SHORTCUTS:
    case rule_utils::rule::MMID_SHORTCUTS_AND_REGEX: {
        std::string_view sc = {};
        for (size_t i = 0; i < rule->matching_parts.size(); ++i) {
            const std::string &part = rule->matching_parts[i];
            if (sc.empty() && part.length() >= SHORTCUT_LENGTH) {
                sc = part;
                break;
            }
        }
        if (!sc.empty()) {
            uint32_t hash = ag::utils::hash(sc.substr(0, SHORTCUT_LENGTH));
            tracelog(log, "Placing a rule in shortcuts table: {} ({})", str, hash);
            int ret;
            khiter_t iter = kh_put(hash_to_indexes, this->shortcuts_table, hash, &ret);
            if (ret < 0) {
                warnlog(log, "Failed to put rule in shortcuts table: {}", str);
                return;
            } else if (ret > 0) {
                // the record is a new one
                std::vector<uint32_t> *positions = new(std::nothrow) std::vector<uint32_t>;
                if (positions == nullptr) {
                    errlog(log, "Failed to allocate memory for shortcuts table");
                    return;
                }
                kh_value(this->shortcuts_table, iter) = positions;
            }
            std::vector<uint32_t> *positions = kh_value(this->shortcuts_table, iter);
            positions->push_back(file_idx);
            break;
        }
        [[fallthrough]];
    }
    case rule_utils::rule::MMID_REGEX:{
        std::vector<std::string> shortcuts = std::move(rule->matching_parts);
        std::transform(shortcuts.begin(), shortcuts.end(), shortcuts.begin(), ag::utils::to_lower);
        std::optional<ag::regex> re = (rule->match_method == rule_utils::rule::MMID_SHORTCUTS)
            ? std::nullopt
            : std::make_optional(ag::regex(rule_utils::get_regex(rule.value())));
        assert(!shortcuts.empty() || re.has_value());
        this->leftovers_table.emplace_back(leftover_entry{ std::move(shortcuts), std::move(re), file_idx });
        tracelog(log, "Rule placed in leftovers table: {}", str);
        break;
    }
    default:
        break;
    }
}

struct rules_stat {
    size_t simple_domain_rules;
    size_t shortcut_rules;
    size_t leftover_rules;
    size_t badfilter_rules;
};

static bool count_rules(uint32_t idx, std::string_view line, void *arg) {
    std::optional<rule_utils::rule> rule = rule_utils::parse(line);
    if (!rule.has_value()) {
        return true;
    }

    rules_stat *stat = (rules_stat *)arg;
    if (rule->public_part.props.test(ag::dnsfilter::RP_BADFILTER)) {
        ++stat->badfilter_rules;
        return true;
    }

    switch (rule->match_method) {
    case rule_utils::rule::MMID_EXACT:
    case rule_utils::rule::MMID_SUBDOMAINS:
        stat->simple_domain_rules += rule->matching_parts.size();
        break;
    case rule_utils::rule::MMID_SHORTCUTS:
    case rule_utils::rule::MMID_SHORTCUTS_AND_REGEX:
        ++stat->shortcut_rules;
        break;
    case rule_utils::rule::MMID_REGEX:
        ++stat->leftover_rules;
        break;
    }

    return true;
}

bool filter::impl::load_line(uint32_t file_idx, std::string_view line, void *arg) {
    filter::impl *f = (filter::impl *)arg;
    f->process_string(line, file_idx);
    return true;
}

int filter::load(const ag::dnsfilter::filter_params &p) {
    size_t last_slash = p.path.rfind('/');
    std::string logger_name = AG_FMT("{}::{}"
        , p.id, (last_slash != p.path.npos) ? &p.path[last_slash + 1] : p.path.c_str());
    this->pimpl->log = ag::create_logger(logger_name);

    ag::file::handle fd = ag::file::open(p.path.data(), ag::file::RDONLY);
    if (!ag::file::is_valid(fd)) {
        errlog(pimpl->log, "Failed to read file: {} ({})",
            p.path, ag::sys::error_string(ag::sys::error_code()));
        return -1;
    }

    rules_stat stat = {};
    ag::file::for_each_line(fd, &count_rules, &stat);

    impl *f = this->pimpl.get();
    kh_resize(hash_to_unique_index, f->unique_domains_table, stat.simple_domain_rules);
    kh_resize(hash_to_indexes, f->shortcuts_table, kh_size(f->shortcuts_table));
    f->leftovers_table.reserve(stat.leftover_rules);
    kh_resize(hash_to_unique_index, f->badfilter_table, stat.badfilter_rules);

    ag::file::set_position(fd, 0);
    int rc = ag::file::for_each_line(fd, &filter::impl::load_line, this->pimpl.get());
    if (rc == 0) {
        this->params = p;
    }
    ag::file::close(fd);

    kh_resize(hash_to_unique_index, f->unique_domains_table, kh_size(f->unique_domains_table));
    kh_resize(hash_to_indexes, f->domains_table, kh_size(f->domains_table));
    kh_resize(hash_to_indexes, f->shortcuts_table, kh_size(f->shortcuts_table));
    f->leftovers_table.shrink_to_fit();
    kh_resize(hash_to_unique_index, f->badfilter_table, kh_size(f->badfilter_table));

    dbglog(pimpl->log, "Unique domains table size: {}", kh_size(f->unique_domains_table));
    dbglog(pimpl->log, "Non-unique domains table size: {}", kh_size(f->domains_table));
    dbglog(pimpl->log, "Shortcuts table size: {}", kh_size(f->shortcuts_table));
    dbglog(pimpl->log, "Leftovers table size: {}", f->leftovers_table.size());
    dbglog(pimpl->log, "Badfilter table size: {}", kh_size(f->badfilter_table));

    return rc;
}

static inline bool match_shortcuts(const std::vector<std::string> &shortcuts, std::string_view domain) {
    size_t seek = 0;
    bool found = false;
    for (const std::string &sc : shortcuts) {
        found = domain.npos != domain.find(sc, seek);
        if (!found) {
            break;
        }
        seek += sc.length();
    }
    return found;
}

bool filter::impl::match_against_line(match_arg &match, std::string_view line) {
    bool matched = false;
    std::optional<rule_utils::rule> rule = rule_utils::parse(line);

    if (!rule.has_value()) {
        matched = true;
        goto exit;
    }

    if (rule->public_part.props.test(ag::dnsfilter::RP_BADFILTER)) {
        matched = true;
        goto exit;
    }

    switch (rule->match_method) {
    case rule_utils::rule::MMID_EXACT:
        for (auto &part : rule->matching_parts) {
            if ((matched = (match.ctx.host == part))) {
                break;
            }
        }
        break;
    case rule_utils::rule::MMID_SUBDOMAINS: {
        for (auto &part : rule->matching_parts) {
            for (auto &subdomain : match.ctx.subdomains) { // assert `subdomains` also contains the full host
                if ((matched = (subdomain == part))) {
                    goto loopexit;
                }
            }
        }
    loopexit:
        break;
    }
    case rule_utils::rule::MMID_SHORTCUTS:
        matched = match_shortcuts(rule->matching_parts, match.ctx.host);
        break;
    case rule_utils::rule::MMID_SHORTCUTS_AND_REGEX:
        assert(rule->matching_parts.size() > 0);
        if (match_shortcuts(rule->matching_parts, match.ctx.host)) {
            ag::regex re(rule_utils::get_regex(rule.value()));
            matched = re.match(match.ctx.host);
        }
        break;
    case rule_utils::rule::MMID_REGEX: {
        ag::regex re = ag::regex(rule_utils::get_regex(rule.value()));
        for (const std::string_view &subdomain : match.ctx.subdomains) {
            if (re.match(subdomain)) {
                matched = true;
                break;
            }
        }
        break;
    }
    default:
        matched = true;
        break;
    }

exit:
    if (matched) {
        dbglog(match.f.pimpl->log, "Domain '{}' matched against rule '{}'", match.ctx.host, line);
        match.ctx.matched_rules.emplace_back(std::move(rule->public_part));
    }
    return matched;
}

static inline bool is_unique_rule(const std::vector<ag::dnsfilter::rule> &rules, std::string_view line) {
    return rules.end() == std::find_if(rules.begin(), rules.end(),
        [&line] (const ag::dnsfilter::rule &rule) { return line == rule.text; });
}

void filter::impl::match_by_file_position(match_arg &match, size_t idx) {
    if (!ag::file::is_valid(match.file)) {
        match.file = ag::file::open(match.f.params.path, ag::file::RDONLY);
        if (!ag::file::is_valid(match.file)) {
            SPDLOG_ERROR("failed to open file to match a domain: {}", match.f.params.path);
            return;
        }
    }

    std::optional<std::string> line = ag::file::read_line(match.file, idx);
    if (!line.has_value()) {
        return;
    }

    if (!is_unique_rule(match.ctx.matched_rules, line.value())) {
        return;
    }

    match_against_line(match, line.value());
}

void filter::impl::search_by_domains(match_arg &match) const {
    for (const std::string_view &domain : match.ctx.subdomains) {
        uint32_t hash = ag::utils::hash(domain);
        khiter_t iter = kh_get(hash_to_unique_index, this->unique_domains_table, hash);
        if (iter != kh_end(this->unique_domains_table)) {
            uint32_t position = kh_value(this->unique_domains_table, iter);
            match_by_file_position(match, position);
            continue;
        }

        iter = kh_get(hash_to_indexes, this->domains_table, hash);
        if (iter != kh_end(this->domains_table)) {
            const std::vector<uint32_t> &positions = *kh_value(this->domains_table, iter);
            for (uint32_t p : positions) {
                match_by_file_position(match, p);
            }
        }
    }
}

void filter::impl::search_by_shortcuts(match_arg &match) const {
    if (match.ctx.host.length() < SHORTCUT_LENGTH) {
        return;
    }

    for (size_t i = 0; i <= match.ctx.host.length() - SHORTCUT_LENGTH; ++i) {
        size_t hash = ag::utils::hash({ &match.ctx.host[i], SHORTCUT_LENGTH });
        khiter_t iter = kh_get(hash_to_indexes, this->shortcuts_table, hash);
        if (iter != kh_end(this->shortcuts_table)) {
            const std::vector<uint32_t> &positions = *kh_value(this->shortcuts_table, iter);
            for (uint32_t p : positions) {
                match_by_file_position(match, p);
            }
        }
    }
}

void filter::impl::search_in_leftovers(match_arg &match) const {
    for (const leftover_entry &entry : this->leftovers_table) {
        const std::vector<std::string> &shortcuts = entry.shortcuts;
        if (!shortcuts.empty() && !match_shortcuts(shortcuts, match.ctx.host)) {
            continue;
        }

        const std::optional<ag::regex> &re = entry.regex;
        if (!re.has_value() || re->match(match.ctx.host)) {
            match_by_file_position(match, entry.file_idx);
        }
    }
}

void filter::impl::search_badfilter_rules(match_arg &match) const {
    for (const ag::dnsfilter::rule &rule : match.ctx.matched_rules) {
        khiter_t iter = kh_get(hash_to_unique_index, this->badfilter_table, ag::utils::hash(rule.text));
        if (iter != kh_end(this->badfilter_table)) {
            match_by_file_position(match, kh_value(this->badfilter_table, iter));
        }
    }
}

void filter::match(match_context &ctx) {
    match_arg m = { ctx, *this, ag::file::INVALID_HANDLE };

    size_t matched_rule_pos = m.ctx.matched_rules.size();

    this->pimpl->search_by_domains(m);
    this->pimpl->search_by_shortcuts(m);
    this->pimpl->search_in_leftovers(m);
    this->pimpl->search_badfilter_rules(m);

    for (; matched_rule_pos < m.ctx.matched_rules.size(); ++matched_rule_pos) {
        m.ctx.matched_rules[matched_rule_pos].filter_id = this->params.id;
    }

    ag::file::close(m.file);
}

filter::match_context filter::create_match_context(std::string_view host) {
    match_context ctx = { ag::utils::to_lower(host), {}, {} };

    size_t n = std::count(ctx.host.begin(), ctx.host.end(), '.');
    if (n > 0) {
        // all except tld
        --n;
    }

    ctx.subdomains.reserve(n + 1);
    ctx.subdomains.emplace_back(ctx.host);
    for (size_t i = 0; i < n; ++i) {
        std::array<std::string_view, 2> parts = ag::utils::split2_by(ctx.subdomains[i], '.');
        ctx.subdomains.emplace_back(parts[1]);
    }

    return ctx;
}
