#include <algorithm>
#include <array>
#include <cassert>
#include <ag_logger.h>
#include <ag_utils.h>
#include <ag_regex.h>
#include <ag_socket_address.h>
#include <ag_net_utils.h>
#include "rule_utils.h"


#define ru_warnlog(l_, ...) do { if ((l_) != nullptr) warnlog(*(l_), __VA_ARGS__); } while (0)


static constexpr int MODIFIERS_MARKER = '$';
static constexpr int MODIFIERS_DELIMITER = ',';
static constexpr std::string_view EXCEPTION_MARKER = "@@";
static constexpr std::string_view SKIPPABLE_PREFIXES[] =
    { "https://", "http://", "http*://", "ws://", "wss://", "ws*://", "://", "//" };
static constexpr std::string_view SPECIAL_SUFFIXES[] =
    { "|", "^", "/" };


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
// INET6_ADDRSTRLEN - 1 (they include the trailing null)
static constexpr size_t MAX_IPADDR_LENTH = 45;


enum match_pattern_mode {
    MPM_NONE = 0,
    MPM_LINE_START_ASSERTED = 1 << 0, // `ample.org` should not match `example.org` (e.g. `|ample.org`)
    MPM_LINE_END_ASSERTED = 1 << 1, // `exampl` should not match `example.org` (e.g. `exampl|`)
    MPM_DOMAIN_START_ASSERTED = 1 << 2, // `example.org` should not match `eeexample.org`,
                                        // but should match `sub.example.org` (e.g. `||example.org`)
};

struct match_info {
    std::string_view text; // matching text without all prefixes
    bool is_regex_rule; // whether the original rule is a regex rule
    bool is_exact_match; // whether only the whole text should be matched, without subdomains matching
    int pattern_mode; // see `match_pattern_mode`
};


static inline bool check_domain_pattern_labels(std::string_view domain) {
    std::vector<std::string_view> labels = ag::utils::split_by(domain, '.');
    for (const std::string_view &label : labels) {
        if (label.length() > MAX_LABEL_LENGTH) {
            return false;
        }
    }
    return true;
}

static inline bool check_domain_pattern_charset(std::string_view domain) {
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

static inline bool is_valid_domain_pattern(std::string_view domain) {
    return domain.length() <= MAX_DOMAIN_LENGTH
        && check_domain_pattern_charset(domain)
        && check_domain_pattern_labels(domain);
}

static inline bool is_eligible_for_subdomains_matching(std::string_view str) {
    if (str.empty()) {
        return false;
    }
    if (std::string_view::npos == str.find('.')) {
        return false; // TLD is not eligible
    }
    // True if it _looks like_ an actual domain name
    return str.front() != '.'
            && str.back() != '.'
            && str.cend() == std::find_if_not(str.cbegin(), str.cend(), [](unsigned char c) {
                return std::isalnum(c) || c == '-' || c == '_' || c == '.';
            });
}

static inline bool is_valid_ip_pattern(std::string_view str) {
    if (str.empty() || str.length() > MAX_IPADDR_LENTH) {
        return false;
    }
    return str.cend() == std::find_if(str.cbegin(), str.cend(), [](unsigned char c) {
        return !(std::isxdigit(c) || c == '.' || c == ':' || c == '[' || c == ']' || c == '*');
    });
}

// https://github.com/AdguardTeam/AdguardHome/wiki/Hosts-Blocklists#-etchosts-syntax
static std::optional<rule_utils::rule> parse_host_file_rule(std::string_view str, ag::logger *log) {
    std::vector<std::string_view> parts = ag::utils::split_by_any_of(str, " \t");
    if (parts.size() < 2) {
        return std::nullopt;
    }
    if (!ag::utils::is_valid_ip4(parts[0]) && !ag::utils::is_valid_ip6(parts[0])) {
        return std::nullopt;
    }
    rule_utils::rule r = {};
    r.match_method = rule_utils::rule::MMID_SUBDOMAINS;
    r.matching_parts.reserve(parts.size() - 1);
    for (size_t i = 1; i < parts.size(); ++i) {
        const std::string_view &domain = parts[i];
        if (domain.empty()) {
            continue;
        }
        if (!is_valid_domain_pattern(domain) || !is_eligible_for_subdomains_matching(domain)) {
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

static bool remove_skippable_prefixes(std::string_view &rule) {
    for (std::string_view prefix : SKIPPABLE_PREFIXES) {
        if (ag::utils::starts_with(rule, prefix)) {
            rule.remove_prefix(prefix.length());
            return true;
        }
    }
    return false;
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

    std::vector<std::string_view> suffixes_to_remove(SPECIAL_SUFFIXES, SPECIAL_SUFFIXES + std::size(SPECIAL_SUFFIXES));
    std::vector<std::string_view>::iterator iter;
    while (suffixes_to_remove.end() != (iter = std::find_if(suffixes_to_remove.begin(), suffixes_to_remove.end(),
            [&rule] (std::string_view suffix) {
                return ag::utils::ends_with(rule, suffix);
            }))) {
        rule.remove_suffix(iter->length());
        r = MPM_LINE_END_ASSERTED;
        suffixes_to_remove.erase(iter);
    }

    return r;
}

static inline bool is_valid_port(std::string_view p) {
    return p.length() <= 5
            && (p.cend() == std::find_if_not(p.cbegin(), p.cend(), [](unsigned char c) { return std::isdigit(c); }));
}

static inline int remove_port(std::string_view &rule) {
    size_t rpos = rule.rfind(':');
    if (rpos == std::string_view::npos) {
        return 0;
    }
    size_t fpos = rule.find(':');
    if (fpos == rpos && (fpos != rule.length() - 1) && is_valid_port(rule.substr(fpos + 1))) {
        rule = rule.substr(0, fpos);
        return MPM_LINE_END_ASSERTED;
    } else if (fpos > 0 && rule[fpos - 1] == ']' && rule[0] == '[') { // IPv6
        rule = rule.substr(1, rpos - 2);
        return MPM_LINE_START_ASSERTED | MPM_LINE_END_ASSERTED;
    }
    return 0;
}

// https://github.com/AdguardTeam/AdguardHome/wiki/Hosts-Blocklists#adblock-style
static match_info extract_match_info(std::string_view rule) {
    match_info info = {.text = rule, .is_regex_rule = check_regex(rule), .is_exact_match = false, .pattern_mode = 0};

    if (info.is_regex_rule) {
        info.text.remove_prefix(1); // begin slash
        info.text.remove_suffix(1); // end slash
        return info;
    }

    // rules with wrong special and skippable prefixes and suffixes will be dropped by
    // domain validity check

    // special prefixes come before skippable ones (e.g. `||http://example.org`)
    // so for the first we should check special ones
    info.pattern_mode |= remove_special_prefixes(info.text);
    bool has_skippable_prefix = remove_skippable_prefixes(info.text);

    info.pattern_mode |= remove_special_suffixes(info.text);
    info.pattern_mode |= remove_port(info.text);

    bool has_wildcard = info.text.npos != info.text.find('*');

    // Exact domain match
    if (!has_wildcard
            && (info.pattern_mode & MPM_LINE_START_ASSERTED)
            && (info.pattern_mode & MPM_LINE_END_ASSERTED)) {
        info.is_exact_match = true;
    }

    // check that rule matches exact domain though it has some special characters
    // rule is like:
    // 1) `||example.org^`
    // 2) `://example.org^`
    // 3) `||example.org:8080`
    if (!has_wildcard
            && (has_skippable_prefix
                    || (info.pattern_mode & MPM_DOMAIN_START_ASSERTED)
                    || (info.pattern_mode & MPM_LINE_START_ASSERTED))
            && (info.pattern_mode & MPM_LINE_END_ASSERTED)) {
        info.pattern_mode = MPM_NONE;
    }

    return info;
}

static inline bool is_host_rule(std::string_view str) {
    std::vector<std::string_view> parts = ag::utils::split_by_any_of(str, " \t");
    return parts.size() > 1
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

    if (!info.is_regex_rule && !is_valid_domain_pattern(str) && !is_valid_ip_pattern(str)) {
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

    bool need_match_by_regex = info.is_regex_rule || info.pattern_mode != MPM_NONE;
    if (!need_match_by_regex) {
        ag::socket_address addr{info.text, 0};
        if (info.is_exact_match && addr.valid()) { // info.text is a valid IP address
            r.match_method = rule::MMID_EXACT;
            r.matching_parts.emplace_back(ag::utils::addr_to_str(addr.addr())); // strip port, compress
        } else if (is_eligible_for_subdomains_matching(str)) {
            r.match_method = info.is_exact_match ? rule::MMID_EXACT : rule::MMID_SUBDOMAINS;
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
            if (shortcuts.size() > 1) {
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
    if (info.is_regex_rule) {
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
