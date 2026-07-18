// adyg_cli — argument parsing & CLI transforms for the pure adyg CLI logic.
//
// This translation unit holds the `+option` keyword table, the dig-compatible
// display-flag helpers and the parse_args() command-line parser (plus the small
// pure decision/rewrite helpers cmd_banner_enabled / apply_force_tcp /
// apply_port). See adyg_cli.h for the public interface; the EDNS/IP helpers
// live in adyg_cli_edns.cpp and the packet/formatting logic in
// adyg_cli_packet.cpp.

#include "adyg_cli.h"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include <fmt/format.h>
#include <ldns/ldns.h>

#include "adyg_cli_internal.h"

namespace ag::adyg {
namespace {

// The kind of a `+option` keyword, driving how parse_args dispatches a matched
// canonical name.
enum class KeywordKind {
    BOOL_CLI,     // toggles a CliOptions boolean (e.g. +short)
    BOOL_DISPLAY, // toggles a DisplayFlags member (e.g. +answer)
    VALUE,        // requires a =value argument (e.g. +timeout=)
    META_ALL,     // +all / +noall: bulk-toggle every display flag
};

struct KeywordDef {
    std::string_view canonical;
    KeywordKind kind;
};

// adyg's canonical `+option` table. Order only affects candidate listing in
// ambiguity errors (parse_args sorts candidates before reporting).
constexpr KeywordDef KEYWORDS[] = {
        {"short", KeywordKind::BOOL_CLI},
        {"tcp", KeywordKind::BOOL_CLI},
        {"trace", KeywordKind::BOOL_CLI},
        {"recurse", KeywordKind::BOOL_CLI},
        {"edns", KeywordKind::BOOL_CLI},
        {"dnssec", KeywordKind::BOOL_CLI},
        {"cdflag", KeywordKind::BOOL_CLI},
        {"qr", KeywordKind::BOOL_CLI},
        {"nsid", KeywordKind::BOOL_CLI},
        {"adflag", KeywordKind::BOOL_CLI},
        {"cookie", KeywordKind::BOOL_CLI},
        // dig-compat no-op toggles (+aaflag/+defname/+showsearch): dig
        // scripts sprinkle them everywhere; adyg accepts them to avoid
        // `unknown option` errors while performing no behavior change (mirrors
        // `dig`, where they are only meaningful with options adyg does not
        // implement, e.g. a resolver search list).
        {"aaflag", KeywordKind::BOOL_CLI},
        {"defname", KeywordKind::BOOL_CLI},
        {"showsearch", KeywordKind::BOOL_CLI},
        {"timeout", KeywordKind::VALUE},
        {"bootstrap", KeywordKind::VALUE},
        {"subnet", KeywordKind::VALUE},
        {"bufsize", KeywordKind::VALUE},
        {"padding", KeywordKind::VALUE},
        {"ednsflags", KeywordKind::VALUE},
        {"ednsopt", KeywordKind::VALUE},
        {"opcode", KeywordKind::VALUE},
        {"cmd", KeywordKind::BOOL_DISPLAY},
        {"comments", KeywordKind::BOOL_DISPLAY},
        {"question", KeywordKind::BOOL_DISPLAY},
        {"answer", KeywordKind::BOOL_DISPLAY},
        {"authority", KeywordKind::BOOL_DISPLAY},
        {"additional", KeywordKind::BOOL_DISPLAY},
        {"stats", KeywordKind::BOOL_DISPLAY},
        {"multiline", KeywordKind::BOOL_DISPLAY},
        {"ttlid", KeywordKind::BOOL_DISPLAY},
        {"class", KeywordKind::BOOL_DISPLAY},
        {"header-only", KeywordKind::BOOL_CLI},
        {"onesoa", KeywordKind::BOOL_DISPLAY},
        {"ttlunits", KeywordKind::BOOL_DISPLAY},
        {"all", KeywordKind::META_ALL},
};

// Applies a display flag by canonical name: sets the corresponding field in `df`
// to `value` and returns true when `canonical` is a recognized display flag
// (cmd/comments/question/answer/authority/additional/stats/multiline/ttlid/
// class/onesoa/ttlunits), false otherwise (callers use the return value for
// display dispatch).
bool apply_display_flag(DisplayFlags &df, std::string_view canonical, bool value) {
    if (canonical == "cmd") {
        df.cmd = value;
    } else if (canonical == "comments") {
        df.comments = value;
    } else if (canonical == "question") {
        df.question = value;
    } else if (canonical == "answer") {
        df.answer = value;
    } else if (canonical == "authority") {
        df.authority = value;
    } else if (canonical == "additional") {
        df.additional = value;
    } else if (canonical == "stats") {
        df.stats = value;
    } else if (canonical == "multiline") {
        df.multiline = value;
    } else if (canonical == "ttlid") {
        df.ttlid = value;
    } else if (canonical == "class") {
        df.cls = value;
    } else if (canonical == "onesoa") {
        df.one_soa = value;
    } else if (canonical == "ttlunits") {
        df.ttl_units = value;
    } else {
        return false;
    }
    return true;
}

void set_all_display_flags(DisplayFlags &df, bool value) {
    // `dig +all` / `+noall` toggle only the section-level display flags (cmd,
    // comments, question, answer, authority, additional, stats). The
    // field-level flags `multiline`, `ttlid` and `cls` are NOT part of the
    // `+all` set: a `+nottlid` / `+noclass` set before `+all` / `+noall` is
    // preserved, and `+noall +answer` still shows TTL and class. Verified
    // against `dig 9.20` (`dig +nottlid +noall +answer` omits the TTL;
    // `dig +noall +answer` keeps it).
    df.cmd = value;
    df.comments = value;
    df.question = value;
    df.answer = value;
    df.authority = value;
    df.additional = value;
    df.stats = value;
}

} // namespace

std::optional<uint16_t> split_plain_host_port(std::string_view &host) {
    // Bracketed IPv6 literal form: `[v6]` or `[v6]:port` (the documented form in
    // docs/adyg.md). The brackets protect the IPv6 literal from being mis-split
    // on one of its own colons, so the only port candidate is the `:port` right
    // after the closing bracket. A bare `[v6]` (no `:port`) yields nullopt and
    // leaves `host` as `[v6]`; on success `host` keeps the brackets so the
    // result is a still-unambiguous IPv6 literal for whichever caller needs it
    // (apply_port -> `[v6]:<newport>`, format_dig_server strips the brackets for
    // dig display). Without this branch the bracketed form has 2+ colons and the
    // single-colon path below would refuse to strip the port — see the
    // `[::1]:53:5353` regression in `ApplyPort.BracketedIpv6WithPort*`.
    if (host.starts_with('[')) {
        const size_t close = host.find(']');
        if (close == std::string_view::npos || close == 1) {
            return std::nullopt; // no closing bracket, or `[]` — not a [v6] literal
        }
        if (close + 1 == host.size()) {
            return std::nullopt; // bare `[v6]`, no port
        }
        if (host[close + 1] != ':') {
            return std::nullopt; // garbage after `]` (e.g. `[::1]foo`); leave untouched
        }
        const std::string_view pstr = host.substr(close + 2);
        unsigned p = 0;
        const auto [e, ec] = std::from_chars(pstr.data(), pstr.data() + pstr.size(), p);
        if (ec != std::errc{} || e != pstr.data() + pstr.size() || p == 0 || p > 65535) {
            return std::nullopt;
        }
        host = host.substr(0, close + 1); // keep the brackets (`[v6]`)
        return static_cast<uint16_t>(p);
    }
    const size_t colon = host.rfind(':');
    if (colon == std::string_view::npos || colon == 0) {
        return std::nullopt; // no colon, or an empty host before it
    }
    // A single colon separates host from port; two or more colons mean a bare
    // IPv6 literal (`::1`, `fe80::1`, …), which must not be mis-split on one of
    // its own colons. Only treat the host as `host:port` when the first and last
    // colon coincide (exactly one colon in the string). The bracketed `[v6]:port`
    // form is handled by the branch above.
    if (host.find(':') != colon) {
        return std::nullopt;
    }
    const std::string_view pstr = host.substr(colon + 1);
    unsigned p = 0;
    const auto [e, ec] = std::from_chars(pstr.data(), pstr.data() + pstr.size(), p);
    if (ec != std::errc{} || e != pstr.data() + pstr.size() || p == 0 || p > 65535) {
        return std::nullopt;
    }
    host = host.substr(0, colon);
    return static_cast<uint16_t>(p);
}

bool cmd_banner_enabled(const CliOptions &opts) {
    // `dig`'s `; <<>> DiG ... <<>>` / `;; global options: +cmd` banner is gated
    // on `+cmd`, but `+short` suppresses it unconditionally — even a later
    // `+cmd` does not bring it back — so `+short` always produces RDATA-only
    // output. Verified against `dig 9.20` (`dig +short +cmd` prints no banner).
    return opts.display.cmd && !opts.short_output;
}

void apply_force_tcp(std::string &server) {
    // Replaces `udp://`/`dns://` schemes with `tcp://` and prefixes bare domains
    // with `tcp://` so that `+tcp` takes effect for plain DNS. Encrypted schemes
    // are left untouched.
    // Scheme matching is case-insensitive (mirroring format_dig_server and the
    // upstream library's `utils::istarts_with`) so `UDP://1.1.1.1` / `Dns://…`
    // are rewritten just like their lowercase forms — otherwise `+tcp` would be
    // silently ignored for uppercase-scheme inputs.
    auto ci_starts_with = [](std::string_view s, std::string_view prefix) {
        return s.size() >= prefix.size() && std::equal(prefix.begin(), prefix.end(), s.begin(), [](char a, char b) {
            return std::tolower(static_cast<unsigned char>(a)) == std::tolower(static_cast<unsigned char>(b));
        });
    };
    if (server.find("://") == std::string::npos) {
        server = "tcp://" + server;
    } else if (ci_starts_with(server, "udp://")) {
        // Replace only the 3-char scheme name (`udp` -> `tcp`), preserving the
        // `://` separator. Replacing 4 chars would drop the colon and yield an
        // invalid `tcp//` URI.
        server.replace(0, 3, "tcp");
    } else if (ci_starts_with(server, "dns://")) {
        server.replace(0, 3, "tcp");
    }
}

void apply_port(std::string &server, std::optional<uint16_t> port) {
    if (!port.has_value() || server.find("://") != std::string::npos) {
        return;
    }
    // Strip an existing explicit `host:port` (only a single `host:port` colon;
    // a bare IPv6 literal — two or more colons — is left alone so it is not
    // mis-split on one of its own colons). This also handles a dot-less hostname
    // carrying an explicit port (e.g. `localhost:53` -> `localhost`), which the
    // old dot-guard skipped, producing an invalid `localhost:53:<port>`.
    std::string_view host = server;
    (void) split_plain_host_port(host); // shortens `host` to the host portion
    server = fmt::format("{}:{}", host, *port);
}

KeywordMatch match_plus_keyword(std::string_view key) {
    // Explicit aliases that are not prefix-matchable (their target canonical
    // does not start with the alias text).
    if (key == "vc") {
        return {.canonical = "tcp"};
    }
    if (key == "do") {
        return {.canonical = "dnssec"};
    }
    if (key == "cd") {
        return {.canonical = "cdflag"};
    }
    // `+rd` / `+rdflag` are dig's aliases for `+recurse` (RD). They are not
    // prefix-matchable because `recurse` does not begin with `rd`.
    if (key == "rd" || key == "rdflag") {
        return {.canonical = "recurse"};
    }
    // Exact canonical match.
    for (const KeywordDef &kw : KEYWORDS) {
        if (kw.canonical == key) {
            return {.canonical = std::string(kw.canonical)};
        }
    }
    // Unambiguous canonical prefix match.
    std::vector<std::string> candidates;
    for (const KeywordDef &kw : KEYWORDS) {
        if (kw.canonical.starts_with(key)) {
            candidates.emplace_back(kw.canonical);
        }
    }
    if (candidates.size() == 1) {
        return {.canonical = candidates[0]};
    }
    if (candidates.empty()) {
        return {.error = fmt::format("unknown option: +{}", key)};
    }
    std::sort(candidates.begin(), candidates.end());
    std::string joined;
    for (size_t i = 0; i < candidates.size(); ++i) {
        if (i != 0) {
            joined += ", ";
        }
        joined += candidates[i];
    }
    return {.error = fmt::format("ambiguous option '+{}', candidates: {}", key, joined)};
}

ParseResult parse_args(int argc, char *argv[]) {
    ParseResult result;
    CliOptions &opts = result.opts;
    bool type_set = false;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-h" || arg == "--help") {
            result.help_requested = true;
            return result;
        }
        if (arg == "-v" || arg == "--version") {
            result.version_requested = true;
            return result;
        }
        if (arg == "-x") {
            // -x <addr>: reverse lookup. Consumes the next argv token as the
            // address and is mutually exclusive with both a positional
            // name/type and the dig-style `-t TYPE` short option (both
            // express the RR type, conflicting with -x fixing it to PTR).
            // `type_set` covers the positional-type AND the `-t TYPE` cases
            // since both set it via the parser below.
            if (type_set) {
                result.error = "-x cannot be combined with a type (positional or -t)";
                return result;
            }
            if (!opts.name.empty()) {
                result.error = "-x cannot be combined with a positional name";
                return result;
            }
            if (i + 1 >= argc) {
                result.error = "option -x requires an address";
                return result;
            }
            std::string addr = argv[++i];
            auto rev = make_reverse_name(addr);
            if (!rev.has_value()) {
                result.error = fmt::format("invalid address for -x: {}", addr);
                return result;
            }
            opts.name = *rev;
            opts.rr_type = LDNS_RR_TYPE_PTR;
            opts.reverse = true;
            continue;
        }
        if (arg == "-4") {
            // IPv4-only: suppress IPv6 bootstrapping (a faithful-enough mirror
            // of dig -4 given the upstream library's ipv6_available knob,
            // which controls bootstrapping, not the socket family directly).
            opts.ipv4_only = true;
            continue;
        }
        if (arg == "-6") {
            // Deliberately unsupported: a symmetric ipv4_available flag would
            // require a cross-layer change. Ship -4 only.
            result.error = "option -6 is not supported (use -4 for IPv4-only queries)";
            return result;
        }
        if (arg == "-p") {
            // -p PORT: override the plain-DNS port without `@IP:PORT` syntax.
            if (i + 1 >= argc) {
                result.error = "option -p requires a port";
                return result;
            }
            std::string_view pstr = argv[++i];
            unsigned port = 0;
            const auto [e, ec] = std::from_chars(pstr.data(), pstr.data() + pstr.size(), port);
            if (ec != std::errc{} || e != pstr.data() + pstr.size() || port == 0 || port > 65535) {
                result.error = fmt::format("invalid port: {}", pstr);
                return result;
            }
            opts.port = static_cast<uint16_t>(port);
            continue;
        }
        if (arg == "-t") {
            // -t TYPE: dig/BIND-style short form for the RR type, equivalent
            // to the positional `adyg name type` form (mirrors `dig`). Consumes
            // the next argv token as a case-insensitive RR-type mnemonic
            // resolved via ldns_get_rr_type_by_name (A, AAAA, MX, TXT, ANY,
            // ...). A `-t TYPE` placed AFTER a positional type overrides it
            // (mirrors `dig example.com A -t AAAA` which queries AAAA — dig
            // also prints an "extra type option" warning that adyg suppresses,
            // since it is gated on dig's multi-query feature which adyg does
            // not implement). A `-t TYPE` placed BEFORE a positional `type`
            // instead yields an "unexpected argument" error: adyg treats any
            // token after `name type` as erroneous rather than emulating
            // dig's behavior of issuing each subsequent `name [type]` as a
            // separate query.
            if (i + 1 >= argc) {
                result.error = "option -t requires a type";
                return result;
            }
            if (opts.reverse) {
                // A prior -x has already set the query name to the
                // .in-addr.arpa / .ip6.arpa reverse-lookup domain and the
                // type to PTR; a -t would override the type to a meaningless
                // value (e.g. an MX query on a .in-addr.arpa name). Reject
                // the combination rather than silently discarding either.
                result.error = "-t cannot be combined with -x";
                return result;
            }
            std::string type_str = argv[++i];
            std::string type_upper = type_str;
            for (char &c : type_upper) {
                c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
            }
            ldns_rr_type type = ldns_get_rr_type_by_name(type_upper.c_str());
            if (type == 0) {
                result.error = fmt::format("unknown RR type: {}", type_str);
                return result;
            }
            opts.rr_type = type;
            type_set = true;
            continue;
        }
        if (arg.starts_with('@')) {
            if (arg.size() == 1) {
                result.error = "empty server after '@'";
                return result;
            }
            // Only one @server is accepted: a second @server is an error
            // (naming both tokens) rather than silently overwriting the first.
            // Multiple servers are not currently supported; they may be added
            // later for dig-style multi-query behavior. docs/adyg.md states
            // "only one server may be given" — the parser now enforces it.
            if (!opts.server.empty()) {
                result.error = fmt::format("multiple @server not supported: {} after @{}", arg, opts.server);
                return result;
            }
            opts.server = arg.substr(1);
        } else if (arg.starts_with('+')) {
            std::string opt = arg.substr(1);
            std::string key;
            std::string value;
            if (size_t eq = opt.find('='); eq != std::string::npos) {
                key = opt.substr(0, eq);
                value = opt.substr(eq + 1);
            } else {
                key = opt;
            }
            // dig-style `+no<opt>` negation: strip a leading "no" (kept distinct
            // from any future canonical that might start with "no").
            bool negate = false;
            std::string base = key;
            if (key.size() > 2 && key.starts_with("no")) {
                negate = true;
                base = key.substr(2);
            }
            KeywordMatch km = match_plus_keyword(base);
            if (!km.error.empty()) {
                result.error = km.error;
                return result;
            }
            const std::string &canon = km.canonical;
            if (canon == "all") {
                set_all_display_flags(opts.display, !negate);
            } else if (canon == "short") {
                opts.short_output = !negate;
            } else if (canon == "tcp") {
                opts.force_tcp = !negate;
            } else if (canon == "trace") {
                opts.trace = !negate;
                if (opts.trace) {
                    // +trace overrides the display-flag defaults (comments, question
                    // and stats off) at this point; a later `+comments`/`+stats`/
                    // `+all` will still take effect (mirrors dig's order-sensitive
                    // precedence).
                    apply_trace_display_defaults(opts.display);
                    // dig's `+trace` also sets `dnssec = true` (the DO bit) —
                    // per-iteration authoritative queries request DNSSEC records
                    // so the trace can show RRSIG/NSEC where present. A later
                    // `+nodnssec` still wins (mirrors `dig +trace +nodnssec`).
                    opts.dnssec = true;
                }
            } else if (canon == "recurse") {
                opts.recurse = !negate;
            } else if (canon == "edns") {
                // dig `+edns[=N]` / `+noedns`: toggle the OPT RR. `+edns`
                // (no value) and `+edns=0` both enable EDNS version 0 (the
                // default); `+edns=N` advertises version N (0..255).
                // `+noedns` disables the default OPT RR. Note: `+dnssec` and
                // `+subnet` still force an OPT RR even under `+noedns` (the DO
                // bit / ECS option live in the OPT record), mirroring `dig`.
                if (negate) {
                    if (!value.empty()) {
                        result.error = fmt::format("option '+{}' does not take a value", key);
                        return result;
                    }
                    opts.edns = false;
                } else {
                    opts.edns = true;
                    if (!value.empty()) {
                        unsigned ver = 0;
                        const auto [ptr, ec] = std::from_chars(value.data(), value.data() + value.size(), ver);
                        if (ec != std::errc{} || ptr != value.data() + value.size() || ver > 255) {
                            result.error = fmt::format("invalid EDNS version: {}", value);
                            return result;
                        }
                        opts.edns_version = static_cast<uint8_t>(ver);
                    } else {
                        opts.edns_version = 0;
                    }
                }
            } else if (canon == "dnssec") {
                opts.dnssec = !negate;
            } else if (canon == "cdflag") {
                opts.cd = !negate;
            } else if (canon == "qr") {
                opts.print_query = !negate;
            } else if (canon == "nsid") {
                // +nsid attaches an EDNS NSID option (RFC 5001) to the query;
                // the server echoes its identity, which adyg prints verbatim.
                opts.nsid = !negate;
            } else if (canon == "adflag") {
                // +adflag (default on) / +noadflag: set/clear the AD
                // (Authenticated Data) bit in the query, mirroring `dig` which
                // sets AD by default to request authenticated-data responses.
                opts.ad = !negate;
            } else if (canon == "cookie") {
                // +cookie (default on) / +nocookie: send/suppress a DNS COOKIE
                // EDNS option (RFC 7873, an 8-byte random client cookie),
                // mirroring `dig` which sends one by default. The cookie is
                // only attached when an OPT RR is present (so `+noedns`
                // suppresses it along with the OPT, matching `dig`).
                opts.cookie = !negate;
            } else if (canon == "header-only") {
                // +header-only: send a spec-compliant header-only query
                // (QDCOUNT=0, no question section), mirroring `dig` which
                // sends a question-less query to probe the server's
                // capabilities. Applied in apply_dns_flags when the query is
                // built; the response is printed normally (per the display
                // flags).
                opts.header_only = !negate;
            } else if (canon == "aaflag" || canon == "defname" || canon == "showsearch") {
                // dig-compat no-op: accepted so common `dig` scripts don't
                // error; adyg performs no behavior change (a resolver search
                // list / AA-set query is not implemented). Negation is
                // likewise accepted and ignored, mirroring `dig`.
            } else if (canon == "timeout") {
                if (negate) {
                    result.error = fmt::format("option '+{}' does not support '+no' form", key);
                    return result;
                }
                // The documented syntax is `+timeout=N`; a bare `+timeout` or
                // `+timeout=` would otherwise fall through to std::from_chars
                // and yield a non-actionable "invalid timeout: " message.
                if (value.empty()) {
                    result.error = "option '+timeout' requires a value: +timeout=N";
                    return result;
                }
                int seconds = 0;
                const auto [ptr, ec] = std::from_chars(value.data(), value.data() + value.size(), seconds);
                if (ec != std::errc{} || ptr != value.data() + value.size() || seconds <= 0) {
                    result.error = fmt::format("invalid timeout: {}", value);
                    return result;
                }
                opts.timeout = std::chrono::seconds{seconds};
            } else if (canon == "bootstrap") {
                if (negate) {
                    result.error = fmt::format("option '+{}' does not support '+no' form", key);
                    return result;
                }
                if (value.empty()) {
                    result.error = "empty bootstrap value";
                    return result;
                }
                opts.bootstrap.emplace_back(value);
            } else if (canon == "subnet") {
                if (negate) {
                    result.error = fmt::format("option '+{}' does not support '+no' form", key);
                    return result;
                }
                if (value.empty()) {
                    result.error = "empty subnet value";
                    return result;
                }
                // Parse ADDR[/PREFIX]; a bare address defaults to the family's
                // full prefix (/32 for IPv4, /128 for IPv6).
                std::string subnet_addr;
                uint8_t prefix = 0;
                if (size_t slash = value.find('/'); slash != std::string::npos) {
                    subnet_addr = value.substr(0, slash);
                    std::string_view pstr = std::string_view(value).substr(slash + 1);
                    unsigned prefix_val = 0;
                    const auto [ptr, ec] = std::from_chars(pstr.data(), pstr.data() + pstr.size(), prefix_val);
                    if (ec != std::errc{} || ptr != pstr.data() + pstr.size() || prefix_val > 128) {
                        result.error = fmt::format("invalid subnet prefix: {}", pstr);
                        return result;
                    }
                    prefix = static_cast<uint8_t>(prefix_val);
                } else {
                    auto fam = parse_ip_addr(value);
                    if (!fam.has_value()) {
                        result.error = fmt::format("invalid subnet address: {}", value);
                        return result;
                    }
                    subnet_addr = value;
                    prefix = (fam->family == 1) ? 32 : 128;
                }
                // Validate address + prefix-in-range together via the encoder.
                if (encode_ecs_option(subnet_addr, prefix).empty()) {
                    result.error = fmt::format("invalid subnet value: {}", value);
                    return result;
                }
                opts.subnet = {.enabled = true, .addr = subnet_addr, .src_prefix = prefix};
            } else if (canon == "bufsize") {
                if (negate) {
                    result.error = fmt::format("option '+{}' does not support '+no' form", key);
                    return result;
                }
                if (value.empty()) {
                    result.error = "option '+bufsize' requires a value: +bufsize=N";
                    return result;
                }
                unsigned bs = 0;
                const auto [ptr, ec2] = std::from_chars(value.data(), value.data() + value.size(), bs);
                if (ec2 != std::errc{} || ptr != value.data() + value.size() || bs == 0 || bs > 65535) {
                    result.error = fmt::format("invalid EDNS buffer size: {}", value);
                    return result;
                }
                opts.edns_bufsize = static_cast<uint16_t>(bs);
            } else if (canon == "padding") {
                if (negate) {
                    result.error = fmt::format("option '+{}' does not support '+no' form", key);
                    return result;
                }
                if (value.empty()) {
                    result.error = "option '+padding' requires a value: +padding=N";
                    return result;
                }
                unsigned pd = 0;
                const auto [ptr, ec2] = std::from_chars(value.data(), value.data() + value.size(), pd);
                if (ec2 != std::errc{} || ptr != value.data() + value.size() || pd > 65535) {
                    result.error = fmt::format("invalid padding length: {}", value);
                    return result;
                }
                opts.padding = static_cast<uint16_t>(pd);
            } else if (canon == "ednsflags") {
                // `+noednsflags` clears the override (dig accepts it); a bare
                // value requires `+ednsflags=0xHH`.
                if (negate) {
                    opts.edns_flags.reset();
                    continue;
                }
                if (value.empty()) {
                    result.error = "option '+ednsflags' requires a value: +ednsflags=0xHH";
                    return result;
                }
                // Accept `0x..`/`0X..` (hex) or a decimal number.
                std::string_view fstr = value;
                int base = 10;
                if (fstr.size() > 2 && fstr[0] == '0' && (fstr[1] == 'x' || fstr[1] == 'X')) {
                    fstr.remove_prefix(2);
                    base = 16;
                }
                unsigned fl = 0;
                const auto [ptr, ec2] = std::from_chars(fstr.data(), fstr.data() + fstr.size(), fl, base);
                if (ec2 != std::errc{} || ptr != fstr.data() + fstr.size() || fl > 0xFFFF) {
                    result.error = fmt::format("invalid EDNS flags: {}", value);
                    return result;
                }
                opts.edns_flags = static_cast<uint16_t>(fl);
            } else if (canon == "ednsopt") {
                // `+ednsopt=CODE[:hexvalue]` (RFC 6891), repeatable. CODE is an
                // EDNS option code — a case-insensitive mnemonic (NSID/ECS/PAD/
                // COOKIE/...) or a decimal number (0..65535); the optional
                // `:hexvalue` is the option-data payload decoded as hex. A bare
                // `+ednsopt` has no code and is an error (dig: "ednsopt no code
                // point specified"). `+noednsopt` clears the list (dig ignores
                // any value, accepts the form unconditionally).
                if (negate) {
                    opts.ednsopts.clear();
                    continue;
                }
                if (value.empty()) {
                    result.error = "option '+ednsopt' requires a code: +ednsopt=CODE[:value]";
                    return result;
                }
                // Split on the FIRST ':' — only the code vs. payload boundary;
                // a ':' inside the payload would be non-hex and is rejected at
                // decode time (dig likewise splits only on the first ':').
                std::string code_str;
                std::string hex_str;
                if (const size_t colon = value.find(':'); colon != std::string::npos) {
                    code_str = value.substr(0, colon);
                    hex_str = value.substr(colon + 1);
                } else {
                    code_str = value;
                }
                const auto opt_code = parse_ednsopt_code(code_str);
                if (!opt_code.has_value()) {
                    result.error = fmt::format("invalid EDNS option code: {}", code_str);
                    return result;
                }
                EdnsOption ednsopt{.code = *opt_code, .data = {}};
                if (!hex_str.empty()) {
                    auto decoded = decode_hex_string(hex_str);
                    if (!decoded.has_value()) {
                        result.error = fmt::format("invalid EDNS option value: {}", hex_str);
                        return result;
                    }
                    ednsopt.data = std::move(*decoded);
                }
                opts.ednsopts.push_back(std::move(ednsopt));
            } else if (canon == "opcode") {
                // `+noopcode` clears the override (dig accepts it).
                if (negate) {
                    opts.opcode.reset();
                    continue;
                }
                if (value.empty()) {
                    result.error = "option '+opcode' requires a value: +opcode=NAME";
                    return result;
                }
                auto op = parse_opcode_name(value);
                if (!op.has_value()) {
                    result.error = fmt::format("invalid opcode: {}", value);
                    return result;
                }
                opts.opcode = op;
            } else if (apply_display_flag(opts.display, canon, !negate)) {
                // display flag toggled above
            } else {
                // Unreachable: match_plus_keyword only returns known canonicals.
                result.error = fmt::format("unknown option: +{}", key);
                return result;
            }
        } else {
            if (opts.reverse) {
                result.error = "-x cannot be combined with a positional name or type";
                return result;
            }
            if (opts.name.empty()) {
                opts.name = arg;
            } else if (!type_set) {
                std::string type_upper = arg;
                for (char &c : type_upper) {
                    c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
                }
                ldns_rr_type type = ldns_get_rr_type_by_name(type_upper.c_str());
                if (type == 0) {
                    result.error = fmt::format("unknown RR type: {}", arg);
                    return result;
                }
                opts.rr_type = type;
                type_set = true;
            } else {
                result.error = fmt::format("unexpected argument: {}", arg);
                return result;
            }
        }
    }
    // Post-parse validation: the OPT record's RDLEN and each EDNS option's
    // option-length are both 16-bit fields, so a request like `+cookie
    // +padding=65535` (or a huge `+ednsopt` hex payload) would otherwise build
    // an EDNS blob > 65535 bytes, yielding a malformed packet / encode-time
    // truncation. Catch it up front with a clear error instead.
    if (std::string e = validate_edns_option_sizes(opts); !e.empty()) {
        result.error = std::move(e);
        return result;
    }
    return result;
}

} // namespace ag::adyg
