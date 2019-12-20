#include <algorithm>
#include <array>
#include <cassert>
#include <ag_logger.h>
#include <ag_utils.h>
#include <ag_regex.h>
#include "rule_utils.h"


#define ru_warnlog(l_, ...) do { if ((l_) != nullptr) warnlog(*(l_), __VA_ARGS__); } while (0)


static constexpr int MODIFIERS_MARKER = '$';
static constexpr int MODIFIERS_DELIMITER = ',';
static constexpr std::string_view EXCEPTION_MARKER = "@@";
static constexpr std::array<std::string_view, 8> SKIPPABLE_PREFIXES =
    { "https", "http", "http*", "ws", "wss", "ws*", ":", "/", };
static constexpr std::array<std::string_view, 1> SKIPPABLE_SUFFIXES =
    { "/", };
static constexpr std::string_view SPECIAL_SUFFIXES[] =
    { "|", "^" };


static const ag::regex SHORTCUT_REGEXES[] =
    {
        // Strip all types of brackets
        ag::regex("([^\\\\]*)\\([^\\\\]*\\)"),
        ag::regex("([^\\\\]*)\\{[^\\\\]*\\}"),
        ag::regex("([^\\\\]*)\\[[^\\\\]*\\]"),
        // Strip some escaped characters
        ag::regex("([^\\\\]*)\\[a-zA-Z]"),
    };

struct supported_modifier_descriptor {
    std::string_view name;
    ag::dnsfilter::rule_props id;
};
static constexpr supported_modifier_descriptor SUPPORTED_MODIFIERS[] = {
    { "important", ag::dnsfilter::RP_IMPORTANT },
    { "badfilter", ag::dnsfilter::RP_BADFILTER },
};

// RFC1035 $2.3.4 Size limits (https://tools.ietf.org/html/rfc1035#section-2.3.4)
static constexpr size_t MAX_DOMAIN_LENGTH = 255;
// RFC1034 $3.5 Preferred name syntax (https://tools.ietf.org/html/rfc1034#section-3.5)
static constexpr size_t MAX_LABEL_LENGTH = 63;


enum match_pattern_mode {
    MPM_NONE = 0,
    MPM_LINE_START_ASSERTED = 1 << 0, // `ample.org` should not match `example.org` (e.g. `|ample.org`)
    MPM_LINE_END_ASSERTED = 1 << 1, // `exampl` should not match `example.org` (e.g. `exampl|`)
    MPM_DOMAIN_START_ASSERTED = 1 << 2, // `example.org` should not match `eeexample.org`,
                                        // but should match `sub.example.org` (e.g. `||example.org`)
};

struct match_info {
    std::string_view text; // matching text without all prefixes
    bool is_regex; // true if rule is regex (e.g. `/example/`)
    int pattern_mode; // see `match_pattern_mode`
};


static inline bool are_valid_domain_labels(std::string_view domain) {
    std::vector<std::string_view> labels = ag::utils::split_by(domain, '.');
    for (const std::string_view &label : labels) {
        if (label.length() > MAX_LABEL_LENGTH) {
            return false;
        }
    }
    return true;
}

static inline bool is_valid_domain_char_set(std::string_view domain) {
    return domain.cend() == std::find_if(domain.cbegin(), domain.cend(),
        [] (int c) -> bool {
            // By RFC1034 $3.5 Preferred name syntax (https://tools.ietf.org/html/rfc1034#section-3.5)
            // plus non-standard:
            //  - '*' for light-weight wildcard regexes
            //  - '_' as it is used by someones
            return !(std::isalpha(c) || std::isdigit(c)
                || c == '.' || c == '-' || c == '*' || c == '_');
        });
}

static inline bool is_valid_domain(std::string_view domain) {
    return domain.length() <= MAX_DOMAIN_LENGTH
        && is_valid_domain_char_set(domain)
        && are_valid_domain_labels(domain);
}

static inline bool is_domain_name(std::string_view str) {
    int first = str.front();
    int last = str.back();
    return (std::isalpha(first) || std::isdigit(first))
        && (std::isalpha(last) || std::isdigit(last))
        && str.find('.') != str.npos
        && str.find('*') == str.npos;
}

// https://github.com/AdguardTeam/AdguardHome/wiki/Hosts-Blocklists#-etchosts-syntax
static std::optional<rule_utils::rule> parse_host_file_rule(std::string_view str, ag::logger *log) {
    std::vector<std::string_view> parts = ag::utils::split_by_any_of(str, " \t");
    if (parts.size() < 2) {
        return std::nullopt;
    }

    rule_utils::rule r = {};
    r.match_method = rule_utils::rule::MMID_DOMAINS;
    r.matching_parts.reserve(parts.size() - 1);
    for (size_t i = 1; i < parts.size(); ++i) {
        const std::string_view &domain = parts[i];
        if (domain.empty()) {
            continue;
        }
        if (!is_valid_domain(domain) || !is_domain_name(domain)) {
            return std::nullopt;
        }
        r.matching_parts.emplace_back(ag::utils::to_lower(domain));
    }

    if (r.matching_parts.empty()) {
        return std::nullopt;
    }

    r.public_part = { 0, std::string(str), {}, std::make_optional(std::string(parts[0])) };
    return std::make_optional(std::move(r));
}

// https://github.com/AdguardTeam/AdguardHome/wiki/Hosts-Blocklists#rule-modifiers
static inline bool extract_modifiers(std::string_view modifiers_str,
        std::bitset<ag::dnsfilter::RP_NUM> *props, ag::logger *log) {
    if (modifiers_str.empty()) {
        return true;
    }

    std::vector<std::string_view> modifiers = ag::utils::split_by(modifiers_str, MODIFIERS_DELIMITER);
    for (const std::string_view &modifier : modifiers) {
        const supported_modifier_descriptor *found = nullptr;
        for (const supported_modifier_descriptor &descr : SUPPORTED_MODIFIERS) {
            if (modifier == descr.name) {
                found = &descr;
                break;
            }
        }
        if (found != nullptr) {
            if (!props->test(found->id)) {
                props->set(found->id);
            } else {
                ru_warnlog(log, "Duplicated modifier: {}", found->name);
                return false;
            }
        } else {
            ru_warnlog(log, "Unknown modifier: {}", modifier);
            return false;
        }
    }
    return true;
}

static inline bool check_regex(std::string_view str) {
    return str.length() > 1 && str.front() == '/' && str.back() == '/';
}

static inline bool remove_skippable_prefixes(std::string_view &rule, bool is_regex) {
    bool removed = false;
    if (!is_regex) {
        decltype(SKIPPABLE_PREFIXES)::const_iterator prefix;
        while (SKIPPABLE_PREFIXES.end() != (prefix = std::find_if(SKIPPABLE_PREFIXES.begin(), SKIPPABLE_PREFIXES.end(),
                [&rule] (std::string_view prefix) { return ag::utils::starts_with(rule, prefix); }))) {
            rule.remove_prefix(prefix->length());
            removed = true;
        }
    } else {
        rule.remove_prefix(1);
        removed = true;
    }
    return removed;
}

static inline bool remove_skippable_suffixes(std::string_view &rule, bool is_regex) {
    bool removed = false;
    if (!is_regex) {
        decltype(SKIPPABLE_SUFFIXES)::const_iterator suffix;
        while (SKIPPABLE_SUFFIXES.end() != (suffix = std::find_if(SKIPPABLE_SUFFIXES.begin(), SKIPPABLE_SUFFIXES.end(),
                [&rule] (std::string_view suffix) { return ag::utils::ends_with(rule, suffix); }))) {
            rule.remove_suffix(suffix->length());
            removed = true;
        }

        // drop trailing part after special suffix (e.g. `example.com^somethig` -> `example.com^`)
        for (std::string_view suffix : SPECIAL_SUFFIXES) {
            // skip the same characters at the begining
            size_t skipped = 0;
            while (skipped < rule.length() && 0 == rule.compare(skipped, suffix.length(), suffix)) {
                skipped += suffix.length();
            }
            std::vector<std::string_view> parts = ag::utils::split_by(rule.substr(skipped), suffix);
            size_t remaining_length = parts[0].length();
            if (parts.size() > 1 || parts[0].length() < rule.length() - skipped) {
                remaining_length += suffix.length();
            }
            rule = { parts[0].data() - skipped, remaining_length + skipped };
        }

        // drop common copy-paste trailers (like `:<port>`, `example.org/<page>`)
        std::vector<std::string_view> parts = ag::utils::split_by_any_of(rule, "/:&");
        removed = removed || parts.size() > 1 || parts[0].length() < rule.length();
        rule = (parts[0].data() == rule.data()) ? parts[0] : "";
    } else {
        rule.remove_suffix(1);
        removed = true;
    }
    return removed;
}

static inline int remove_special_prefixes(std::string_view &rule) {
    if (ag::utils::starts_with(rule, "||")) {
        rule.remove_prefix(2);
        return MPM_DOMAIN_START_ASSERTED;
    }

    if (rule.front() == '|') {
        rule.remove_prefix(1);
        return MPM_LINE_START_ASSERTED;
    }

    return MPM_NONE;
}

static inline int remove_special_suffixes(std::string_view &rule) {
    int r = MPM_NONE;
    for (std::string_view suffix : SPECIAL_SUFFIXES) {
        if (ag::utils::ends_with(rule, suffix)) {
            rule.remove_suffix(suffix.length());
            r = MPM_LINE_END_ASSERTED;
        }
    }
    return r;
}

// https://github.com/AdguardTeam/AdguardHome/wiki/Hosts-Blocklists#adblock-style
static match_info extract_match_info(std::string_view rule) {
    match_info info = { rule, check_regex(rule), 0 };

    // special prefixes come before skippable ones (e.g. `||http://example.org`)
    // so for the first we should check special ones
    if (!info.is_regex) {
        info.pattern_mode |= remove_special_prefixes(info.text);
    }

    bool has_skippable_prefix = remove_skippable_prefixes(info.text, info.is_regex);
    // but special suffixes come after skippable ones (e.g. `example.org^asd`)
    // so for the first we should drop skippable ones
    bool has_skippable_suffix = remove_skippable_suffixes(info.text, info.is_regex);

    if (!info.is_regex) {
        info.pattern_mode |= remove_special_suffixes(info.text);
    }

    // check that rule matches exact domain though it has some special characters
    if (!info.is_regex) {
        // rule is like:
        // 1) `||example.org^`
        // 2) `://example.org^`
        // 3) `||example.org:8080`
        bool domain_start_asserted = has_skippable_prefix
            || (info.pattern_mode & MPM_LINE_START_ASSERTED)
            || (info.pattern_mode & MPM_DOMAIN_START_ASSERTED);

        bool domain_end_asserted = has_skippable_suffix
            || (info.pattern_mode & MPM_LINE_END_ASSERTED);

        if (info.text.find('*') == info.text.npos && domain_start_asserted && domain_end_asserted) {
            info.pattern_mode = MPM_NONE;
        }
    }

    return info;
}

static inline bool is_host_rule(std::string_view str) {
    std::vector<std::string_view> parts = ag::utils::split_by_any_of(str, " \t");
    return parts.size() > 0
            && (ag::utils::is_valid_ip4(parts[0]) || ag::utils::is_valid_ip6(parts[0]));
}

std::optional<rule_utils::rule> rule_utils::parse(std::string_view str, ag::logger *log) {
    std::string_view orig_str = str;
    if (str.empty() || is_comment(str)) {
        return std::nullopt;
    }

    if (is_host_rule(str)) {
        return parse_host_file_rule(str, log);
    }

    std::bitset<ag::dnsfilter::RP_NUM> props;
    if (ag::utils::starts_with(str, EXCEPTION_MARKER)) {
        str.remove_prefix(EXCEPTION_MARKER.length());
        props.set(ag::dnsfilter::RP_EXCEPTION);
    }

    std::array<std::string_view, 2> parts = { str, {} };
    if (!check_regex(str)) {
        parts = ag::utils::rsplit2_by(str, MODIFIERS_MARKER);
        str = parts[0];
    }

    match_info info = extract_match_info(str);
    str = info.text;
    if (str.empty() || str.find_first_not_of(".*") == str.npos) {
        ru_warnlog(log, "Too wide rule: {}", str);
        return std::nullopt;
    }

    if (!info.is_regex && !is_valid_domain(str)) {
        ru_warnlog(log, "Invalid domain name: {}", str);
        return std::nullopt;
    }

    if (!extract_modifiers(parts[1], &props, log)) {
        return std::nullopt;
    }

    rule r = { { 0, std::string(orig_str), props, std::nullopt }, {}, {} };
    if (props.test(ag::dnsfilter::RP_BADFILTER)) {
        return std::make_optional(std::move(r));
    }

    bool need_match_by_regex = info.is_regex || info.pattern_mode != MPM_NONE;
    if (!need_match_by_regex) {
        if (is_domain_name(str)) {
            r.match_method = rule::MMID_DOMAINS;
            r.matching_parts.emplace_back(ag::utils::to_lower(str));
        } else {
            r.match_method = rule::MMID_SHORTCUTS;
            std::vector<std::string_view> shortcuts = ag::utils::split_by(str, '*');
            r.matching_parts.reserve(shortcuts.size());
            for (const std::string_view &sc : shortcuts) {
                r.matching_parts.emplace_back(ag::utils::to_lower(sc));
            }
        }
    } else {
        if (str.find('?') != str.npos) {
            r.match_method = rule::MMID_REGEX;
        } else {
            #define SPECIAL_CHAR_PLACEHOLDER "..."
            std::string text(str);
            for (const ag::regex &re : SHORTCUT_REGEXES) {
                if (re.is_valid()) {
                    text = re.replace(text, "$1" SPECIAL_CHAR_PLACEHOLDER);
                }
            }

            static constexpr std::string_view SPECIAL_CHARACTERS = "\\^$*+?.()|[]{}";
            std::vector<std::string_view> shortcuts = ag::utils::split_by_any_of(text, SPECIAL_CHARACTERS);
            if (shortcuts.size() > 0) {
                r.match_method = rule::MMID_SHORTCUTS_AND_REGEX;
                r.matching_parts.reserve(shortcuts.size());
                for (const std::string_view &sc : shortcuts) {
                    r.matching_parts.emplace_back(ag::utils::to_lower(sc));
                }
            } else {
                r.match_method = rule::MMID_REGEX;
                r.matching_parts.emplace_back(ag::utils::to_lower(str));
            }
        }

        std::string re = rule_utils::get_regex(r);
        if (!ag::regex(re).is_valid()) {
            ru_warnlog(log, "Invalid regex: {}", re);
            return std::nullopt;
        }
    }

    return std::make_optional(std::move(r));
}

std::string rule_utils::get_regex(const rule &r) {
    assert(r.match_method == rule::MMID_REGEX || r.match_method == rule::MMID_SHORTCUTS_AND_REGEX);

    std::string_view text = r.public_part.text;
    if (ag::utils::starts_with(text, EXCEPTION_MARKER)) {
        text.remove_prefix(EXCEPTION_MARKER.length());
    }

    if (text.front() != '/' || text.back() != '/') {
        std::array<std::string_view, 2> parts = ag::utils::rsplit2_by(text, MODIFIERS_MARKER);
        text = parts[0];
    }

    match_info info = extract_match_info(text);
    if (info.is_regex) {
        return std::string(info.text);
    }

    bool assert_line_start = info.pattern_mode & MPM_LINE_START_ASSERTED;
    bool assert_domain_start = info.pattern_mode & MPM_DOMAIN_START_ASSERTED;
    bool assert_end = info.pattern_mode & MPM_LINE_END_ASSERTED;

    std::string re = AG_FMT("{}{}{}"
            , assert_line_start ? "^" : (assert_domain_start ? "^(*.)?" : "")
            , info.text
            , assert_end ? "$" : "");
    size_t n = std::count_if(re.begin(), re.end(), [] (int ch) { return ch == '*' || ch == '.'; });
    if (n > 0) {
        std::string tmp;
        tmp.reserve(re.length() + n);
        for (size_t i = 0; i < re.length(); ++i) {
            int ch = re[i];
            switch (ch) {
            case '*':
                tmp.push_back('.');
                break;
            case '.':
                tmp.push_back('\\');
                break;
            }
            tmp.push_back(ch);
        }
        std::swap(tmp, re);
    }

    return re;
}

std::string rule_utils::get_text_without_badfilter(const ag::dnsfilter::rule &r) {
    constexpr std::string_view BADFILTER_MODIFIER = "badfilter";

    std::array<std::string_view, 2> parts = ag::utils::rsplit2_by(r.text, MODIFIERS_MARKER);
    size_t bf_pos = parts[1].find(BADFILTER_MODIFIER.data());
    size_t after_bf_pos = bf_pos + BADFILTER_MODIFIER.length();

    std::string_view prefix = { parts[0].data(), parts[0].length() + 1 + bf_pos };
    std::string_view suffix = { parts[1].data() + after_bf_pos, parts[1].length() - after_bf_pos };
    if (prefix.back() == ','
            || (suffix.length() == 0 && prefix.back() == '$')) {
        prefix.remove_suffix(1);
    } else if (suffix.front() == ',' && prefix.back() == '$') {
        suffix.remove_prefix(1);
    }

    return AG_FMT("{}{}", prefix, suffix);
}
