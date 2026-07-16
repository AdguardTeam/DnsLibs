// adig_cli — implementation of the pure (event-loop-free) adig CLI logic.
//
// See adig_cli.h for the interface description.

#include "adig_cli.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <cstdint>
#include <cstdlib>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>

#include <fmt/format.h>
#include <ldns/ldns.h>

#include "dns/common/net_consts.h"

namespace ag::adig {
namespace {

// RAII wrapper for ldns malloc'd strings (char pointers returned by
// ldns_rdf2str, ldns_rr_type2str, etc.) — they must be freed with free().
using ag::AllocatedPtr;

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

// adig's canonical `+option` table. Order only affects candidate listing in
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
        {"timeout", KeywordKind::VALUE},
        {"bootstrap", KeywordKind::VALUE},
        {"subnet", KeywordKind::VALUE},
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
        {"all", KeywordKind::META_ALL},
};

// Returns the KeywordDef for a canonical name, or nullptr if `canonical` is not
// a display flag (callers only use this for display dispatch).
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

// Parse an IPv4/IPv6 literal into its EDNS family code (1 / 2) and address
// bytes. Returns nullopt for anything that is not a valid address literal.
// Used by both make_reverse_name (reverse-DNS name) and encode_ecs_option
// (ECS option) so the IP-parsing logic lives in exactly one place.
struct ParsedAddr {
    uint16_t family = 0;             // 1 = IPv4, 2 = IPv6
    std::array<uint8_t, 16> bytes{}; // first `len` bytes hold the address
    size_t len = 0;                  // 4 for IPv4, 16 for IPv6
};

std::optional<ParsedAddr> parse_ip_addr(std::string_view addr) {
    if (addr.empty()) {
        return std::nullopt;
    }
    const std::string s(addr); // ldns requires a null-terminated C string
    std::unique_ptr<ldns_rdf, void (*)(ldns_rdf *)> rdf(
            ldns_rdf_new_frm_str(LDNS_RDF_TYPE_A, s.c_str()), &ldns_rdf_deep_free);
    if (rdf != nullptr) {
        ParsedAddr p{.family = 1, .len = 4};
        std::copy_n(ldns_rdf_data(rdf.get()), 4, p.bytes.begin());
        return p;
    }
    rdf.reset(ldns_rdf_new_frm_str(LDNS_RDF_TYPE_AAAA, s.c_str()));
    if (rdf != nullptr) {
        ParsedAddr p{.family = 2, .len = 16};
        std::copy_n(ldns_rdf_data(rdf.get()), 16, p.bytes.begin());
        return p;
    }
    return std::nullopt;
}

// Compute the wire-format size of a packet. ldns caches the size only for
// packets parsed from wire bytes; freshly-built query packets report 0, so we
// force a round-trip through ldns_pkt2wire in that case.
size_t wire_pkt_size(const ldns_pkt *pkt) {
    if (pkt == nullptr) {
        return 0;
    }
    size_t cached = ldns_pkt_size(pkt);
    if (cached != 0) {
        return cached;
    }
    uint8_t *wire = nullptr;
    size_t sz = 0;
    if (ldns_pkt2wire(&wire, pkt, &sz) == LDNS_STATUS_OK) {
        AllocatedPtr<uint8_t> owned(wire);
        (void) owned;
        return sz;
    }
    return 0;
}

// Build the lowercase flag string dig prints in the header, e.g. "qr rd ra".
// The DO bit is shown in the OPT PSEUDOSECTION, not in the header flags.
std::string pkt_flags_str(const ldns_pkt *pkt) {
    std::string s;
    if (ldns_pkt_qr(pkt)) {
        s += " qr";
    }
    if (ldns_pkt_aa(pkt)) {
        s += " aa";
    }
    if (ldns_pkt_tc(pkt)) {
        s += " tc";
    }
    if (ldns_pkt_rd(pkt)) {
        s += " rd";
    }
    if (ldns_pkt_ra(pkt)) {
        s += " ra";
    }
    if (ldns_pkt_ad(pkt)) {
        s += " ad";
    }
    if (ldns_pkt_cd(pkt)) {
        s += " cd";
    }
    return s;
}

// Format a single RR in dig-compatible text. When `with_ttl` is false the TTL
// field is omitted (dig +nottlid); when `with_class` is false the class field
// is omitted (dig +noclass). Question-section RRs are always printed without
// TTL/RDATA and are prefixed with ';' (dig convention).
std::string format_rr_dig(const ldns_rr *rr, bool with_ttl, bool with_class, bool is_question) {
    std::string out;
    if (is_question) {
        out += ';';
    }
    AllocatedPtr<char> owner(ldns_rdf2str(ldns_rr_owner(rr)));
    out += (owner != nullptr) ? owner.get() : "";
    out += '\t';
    if (with_ttl && !is_question) {
        out += fmt::format("{}\t", ldns_rr_ttl(rr));
    }
    if (with_class) {
        AllocatedPtr<char> cls(ldns_rr_class2str(ldns_rr_get_class(rr)));
        out += (cls != nullptr) ? cls.get() : "IN";
        out += '\t';
    }
    AllocatedPtr<char> type(ldns_rr_type2str(ldns_rr_get_type(rr)));
    out += (type != nullptr) ? type.get() : "";
    if (!is_question) {
        size_t rd_count = ldns_rr_rd_count(rr);
        for (size_t i = 0; i < rd_count; ++i) {
            AllocatedPtr<char> rdf_str(ldns_rdf2str(ldns_rr_rdf(rr, i)));
            if (rdf_str != nullptr) {
                out += '\t';
                out += rdf_str.get();
            }
        }
    }
    out += '\n';
    return out;
}

} // namespace

bool cmd_banner_enabled(const CliOptions &opts) {
    // `dig`'s `; <<>> DiG ... <<>>` / `;; global options: +cmd` banner is gated
    // on `+cmd`, but `+short` suppresses it unconditionally — even a later
    // `+cmd` does not bring it back — so `+short` always produces RDATA-only
    // output. Verified against `dig 9.20` (`dig +short +cmd` prints no banner).
    return opts.display.cmd && !opts.short_output;
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

std::optional<std::string> make_reverse_name(std::string_view addr) {
    auto parsed = parse_ip_addr(addr);
    if (!parsed.has_value()) {
        return std::nullopt;
    }
    if (parsed->family == 1) {
        return fmt::format(
                "{}.{}.{}.{}.in-addr.arpa.", parsed->bytes[3], parsed->bytes[2], parsed->bytes[1], parsed->bytes[0]);
    }
    // IPv6: 16 address bytes -> 32 reversed nibbles, dot-separated.
    static constexpr char HEX[] = "0123456789abcdef";
    std::string out;
    out.reserve(2 * 32 + static_cast<size_t>(sizeof("ip6.arpa.")));
    for (int i = 15; i >= 0; --i) {
        uint8_t b = parsed->bytes[i];
        out += HEX[b & 0x0F];
        out += '.';
        out += HEX[(b >> 4) & 0x0F];
        out += '.';
    }
    out += "ip6.arpa.";
    return out;
}

ldns_pkt_ptr make_query(const std::string &name, ldns_rr_type type, bool recurse) {
    std::string fqdn = name;
    if (!fqdn.empty() && fqdn.back() != '.') {
        fqdn += '.';
    }
    ldns_rdf *dname = ldns_dname_new_frm_str(fqdn.c_str());
    if (dname == nullptr) {
        return {nullptr};
    }
    ldns_pkt *pkt = ldns_pkt_query_new(dname, type, LDNS_RR_CLASS_IN, recurse ? LDNS_RD : 0);
    if (pkt == nullptr) {
        // ldns_pkt_query_new did not consume `dname` on failure, so it must be
        // freed here to avoid a leak (mirrors the explicit free on this error
        // path in other call sites, e.g. dnscrypt/dns_crypt_ldns.cpp).
        ldns_rdf_deep_free(dname);
        return {nullptr};
    }
    ldns_pkt_set_random_id(pkt);
    return ldns_pkt_ptr(pkt);
}

std::vector<uint8_t> encode_ecs_option(std::string_view addr, uint8_t src_prefix) {
    auto parsed = parse_ip_addr(addr);
    if (!parsed.has_value()) {
        return {};
    }
    const uint8_t max_prefix = (parsed->family == 1) ? 32 : 128;
    if (src_prefix > max_prefix) {
        return {};
    }
    // option-data = family(2 BE) + source-prefix-len(1) + scope-prefix-len(1=0)
    //               + address (ceil(src_prefix/8) bytes, bits past the prefix
    //               in the last byte cleared).
    const size_t addr_len = static_cast<size_t>((src_prefix + 7) / 8);
    const uint8_t remainder = static_cast<uint8_t>(src_prefix % 8);
    std::vector<uint8_t> data;
    data.reserve(4 + addr_len);
    data.push_back(static_cast<uint8_t>((parsed->family >> 8) & 0xFF));
    data.push_back(static_cast<uint8_t>(parsed->family & 0xFF));
    data.push_back(src_prefix);
    data.push_back(0); // scope prefix-length (client->server: always 0)
    for (size_t i = 0; i < addr_len; ++i) {
        uint8_t b = parsed->bytes[i];
        if (i + 1 == addr_len && remainder != 0) {
            // Keep only the top `remainder` bits of the last address byte.
            b &= static_cast<uint8_t>(0xFF << (8 - remainder));
        }
        data.push_back(b);
    }
    // Full EDNS option TLV: option-code(2 BE) + option-length(2 BE) + option-data.
    // This is exactly the bytes ldns stores as the packet's EDNS data and writes
    // verbatim as the OPT RR's RDATA.
    std::vector<uint8_t> tlv;
    tlv.reserve(4 + data.size());
    tlv.push_back(0x00);
    tlv.push_back(0x08); // option code 8 = Client Subnet (RFC 7871)
    const uint16_t len = static_cast<uint16_t>(data.size());
    tlv.push_back(static_cast<uint8_t>((len >> 8) & 0xFF));
    tlv.push_back(static_cast<uint8_t>(len & 0xFF));
    tlv.insert(tlv.end(), data.begin(), data.end());
    return tlv;
}

void apply_dns_flags(ldns_pkt *pkt, const CliOptions &opts) {
    if (pkt == nullptr) {
        return;
    }
    // Determine whether an OPT RR must be present. `+edns` (the default) and
    // `+dnssec` / `+subnet` all require one. `+noedns` (opts.edns == false)
    // suppresses the default OPT only when no EDNS-bearing option forces it —
    // mirroring `dig`, where `+dnssec`/`+subnet` still attach an OPT RR under
    // `+noedns` (the DO bit / ECS option live in the OPT record).
    const bool want_edns = opts.edns || opts.dnssec || opts.subnet.enabled;
    if (!want_edns) {
        // Only the header-level CD bit (below) may still apply.
        if (opts.cd) {
            ldns_pkt_set_cd(pkt, true);
        }
        return;
    }
    // Advertising a >0 EDNS UDP payload size is what makes ldns synthesize the
    // OPT pseudo-RR on the wire (ldns_pkt_edns() returns true once the UDP
    // size is non-zero).
    ldns_pkt_set_edns_udp_size(pkt, static_cast<uint16_t>(dns::UDP_RECV_BUF_SIZE));
    ldns_pkt_set_edns_version(pkt, opts.edns_version);
    if (opts.dnssec) {
        // RFC 3225: set the DO bit so the upstream returns DNSSEC records
        // (RRSIG etc.). Mirrors the proxy's DnssecHelpers::set_do_bit.
        ldns_pkt_set_edns_do(pkt, true);
    }
    if (opts.cd) {
        // Checking Disabled: ask the upstream to skip DNSSEC validation.
        ldns_pkt_set_cd(pkt, true);
    }
    if (opts.subnet.enabled) {
        // Attach the ECS option as the OPT RR's RDATA. ldns writes the rdf bytes
        // verbatim (LDNS_RDF_TYPE_NONE is a direct copy on both encode/decode).
        std::vector<uint8_t> tlv = encode_ecs_option(opts.subnet.addr, opts.subnet.src_prefix);
        if (!tlv.empty()) {
            ldns_rdf *rdf = ldns_rdf_new_frm_data(LDNS_RDF_TYPE_NONE, tlv.size(), tlv.data());
            if (rdf != nullptr) {
                // The packet takes ownership of `rdf` (it is freed with the pkt).
                ldns_pkt_set_edns_data(pkt, rdf);
            }
        }
    }
}

std::map<std::string, GlueAddress> additional_glue(const ldns_pkt *pkt) {
    std::map<std::string, GlueAddress> glue;
    if (pkt == nullptr) {
        return glue;
    }
    const ldns_rr_list *additional = ldns_pkt_additional(pkt);
    if (additional == nullptr) {
        return glue;
    }
    for (size_t i = 0; i < ldns_rr_list_rr_count(additional); ++i) {
        const ldns_rr *rr = ldns_rr_list_rr(additional, i);
        ldns_rr_type type = ldns_rr_get_type(rr);
        if (type != LDNS_RR_TYPE_A && type != LDNS_RR_TYPE_AAAA) {
            continue;
        }
        AllocatedPtr<char> owner(ldns_rdf2str(ldns_rr_owner(rr)));
        AllocatedPtr<char> addr(ldns_rdf2str(ldns_rr_rdf(rr, 0)));
        if (owner == nullptr || addr == nullptr) {
            continue;
        }
        // Prefer A over AAAA: an A record always wins (overwriting any prior
        // AAAA for the same owner), and an AAAA is kept only when no A was seen
        // for that owner. This prevents a later AAAA from displacing an earlier
        // A in the ADDITIONAL section, so +trace neither prefers IPv6 when IPv4
        // glue is present nor makes the chosen address depend on RR ordering.
        if (type == LDNS_RR_TYPE_A) {
            glue.insert_or_assign(owner.get(), GlueAddress{addr.get(), false});
        } else {
            glue.try_emplace(owner.get(), GlueAddress{addr.get(), true});
        }
    }
    return glue;
}

bool glue_address_usable(const GlueAddress &glue, bool ipv4_only) {
    // -4 (ipv4_only) suppresses IPv6 so a literal IPv6 address is never passed
    // to trace_exchange() (ipv6_available only governs AAAA bootstrapping, not
    // dialing a literal IPv6 peer).
    return !(ipv4_only && glue.ipv6);
}

std::string format_packet_dig(
        const ldns_pkt *pkt, const DisplayFlags &flags, bool is_query, Millis query_time, std::string_view server) {
    if (pkt == nullptr) {
        return {};
    }
    std::string out;

    // Header (opcode, status, id, flags, counts).
    if (flags.comments) {
        out += is_query ? ";; Sending:\n" : ";; Got answer:\n";
        AllocatedPtr<char> opcode(ldns_pkt_opcode2str(ldns_pkt_get_opcode(pkt)));
        AllocatedPtr<char> rcode(ldns_pkt_rcode2str(ldns_pkt_get_rcode(pkt)));
        out += fmt::format(";; ->>HEADER<<- opcode: {}, status: {}, id: {}\n", (opcode != nullptr) ? opcode.get() : "",
                (rcode != nullptr) ? rcode.get() : "", ldns_pkt_id(pkt));
        // dig counts the OPT RR in ADDITIONAL; ldns stores it separately.
        size_t arcount = ldns_pkt_arcount(pkt);
        if (ldns_pkt_edns(pkt)) {
            ++arcount;
        }
        std::string fstr = pkt_flags_str(pkt);
        out += fmt::format(";; flags:{}; QUERY: {}, ANSWER: {}, AUTHORITY: {}, ADDITIONAL: {}\n\n",
                fstr.empty() ? "" : fstr, ldns_pkt_qdcount(pkt), ldns_pkt_ancount(pkt), ldns_pkt_nscount(pkt), arcount);
    }

    // OPT PSEUDOSECTION (shown before QUESTION in dig, gated on +additional
    // and +comments — dig's trace default suppresses it entirely).
    if (flags.comments && flags.additional && ldns_pkt_edns(pkt)) {
        out += ";; OPT PSEUDOSECTION:\n";
        std::string edns_flags;
        if (ldns_pkt_edns_do(pkt)) {
            edns_flags = " do";
        }
        out += fmt::format("; EDNS: version: {}, flags:{}; udp: {}\n", ldns_pkt_edns_version(pkt), edns_flags,
                ldns_pkt_edns_udp_size(pkt));
        // Show EDNS option data (e.g. ECS) as a hex dump when present.
        ldns_rdf *data = ldns_pkt_edns_data(pkt);
        if (data != nullptr) {
            const uint8_t *bytes = ldns_rdf_data(data);
            size_t sz = ldns_rdf_size(data);
            out += fmt::format("; DATA: \\# {} ", sz);
            for (size_t i = 0; i < sz; ++i) {
                out += fmt::format("{:02x}", bytes[i]);
            }
            out += '\n';
        }
        out += '\n';
    }

    // QUESTION / ANSWER / AUTHORITY / ADDITIONAL sections.
    auto print_section = [&](const char *title, const ldns_rr_list *list, bool is_question) {
        if (list == nullptr || ldns_rr_list_rr_count(list) == 0) {
            // dig suppresses empty-section output entirely (no header, no
            // following blank line) — including the `* SECTION:` titles even
            // when `+comments` is on.
            return;
        }
        // Section headers (and the trailing blank line that follows) are
        // `comments`. `dig +nocomments` / the trace-mode default emit just the
        // RRs concatenated; section toggles (`+answer` etc.) gate the RRs.
        if (flags.comments) {
            out += fmt::format(";; {} SECTION:\n", title);
        }
        for (size_t i = 0; i < ldns_rr_list_rr_count(list); ++i) {
            const ldns_rr *rr = ldns_rr_list_rr(list, i);
            // OPT is shown in OPT PSEUDOSECTION, not ADDITIONAL.
            if (ldns_rr_get_type(rr) == LDNS_RR_TYPE_OPT) {
                continue;
            }
            out += format_rr_dig(rr, flags.ttlid, flags.cls, is_question);
        }
        if (flags.comments) {
            out += '\n';
        }
    };

    if (flags.question) {
        print_section("QUESTION", ldns_pkt_question(pkt), true);
    }
    if (flags.answer) {
        print_section("ANSWER", ldns_pkt_answer(pkt), false);
    }
    if (flags.authority) {
        print_section("AUTHORITY", ldns_pkt_authority(pkt), false);
    }
    if (flags.additional) {
        print_section("ADDITIONAL", ldns_pkt_additional(pkt), false);
    }

    // Stats trailer (query time, server, message size).
    if (flags.stats) {
        // A zero query_time (e.g. the `+qr` query echo, which has not been sent
        // yet) omits the line, matching the documented contract and `dig +qr`
        // (which prints only `;; MSG SIZE  sent:` for the query packet).
        if (query_time.count() != 0) {
            out += fmt::format(";; Query time: {} msec\n", query_time.count());
        }
        if (!server.empty()) {
            out += fmt::format(";; SERVER: {}\n", server);
        }
        size_t sz = wire_pkt_size(pkt);
        out += fmt::format(";; MSG SIZE  {}: {}\n", is_query ? "sent" : "rcvd", sz);
    }

    return out;
}

void apply_trace_display_defaults(DisplayFlags &flags) {
    // `dig +trace` clears `comments`, `question`, and `stats`. The other
    // section toggles are left at their default (on), so the per-hop body
    // becomes just the answer/authority/additional RRs without section
    // headers. The trace-specific "Received ... bytes from ..." footer is
    // emitted by `format_trace_packet_dig` in place of the standard stats
    // block. See `setup_trace` in dig's dighost.c (the order-sensitive
    // semantics mirror dig exactly: a `+comments` *after* `+trace` still
    // re-enables comments).
    flags.comments = false;
    flags.question = false;
    flags.stats = false;
    // These stay on (dig prints ANSWER/AUTHORITY/ADDITIONAL RRs in trace):
    flags.cmd = true;
    flags.answer = true;
    flags.authority = true;
    flags.additional = true;
    // Multiline / ttlid / cls are untouched (their defaults apply).
}

std::string format_trace_received_line(
        Millis query_time, size_t bytes, std::string_view server_ip, std::string_view server_name) {
    // Mirrors dig's ";; Received <n> bytes from <IP>#53(<NAME>) in <ms> ms".
    // When the peer has no resolvable name dig repeats the IP inside parens.
    std::string name(server_name);
    if (name.empty()) {
        name = std::string(server_ip);
    }
    if (server_ip.empty()) {
        // Degenerate input (no server recorded); fall back to name only to
        // avoid producing a malformed `#53()` fragment.
        return fmt::format(";; Received {} bytes from {}#53 in {} ms\n", bytes, name, query_time.count());
    }
    return fmt::format(";; Received {} bytes from {}#53({}) in {} ms\n", bytes, server_ip, name, query_time.count());
}

std::string format_trace_packet_dig(const ldns_pkt *pkt, const DisplayFlags &flags, Millis query_time,
        std::string_view server_ip, std::string_view server_name) {
    if (pkt == nullptr) {
        return {};
    }
    // Build the per-hop body using `format_packet_dig` with the standard stats
    // block suppressed (we emit either the trace `Received` line or a
    // trace-flavored stats footer ourselves below). An empty `server` keeps
    // `format_packet_dig` from emitting its own `;; SERVER:` line.
    DisplayFlags body_flags = flags;
    body_flags.stats = false;
    std::string out = format_packet_dig(pkt, body_flags, false, Millis{0}, "");

    size_t sz = wire_pkt_size(pkt);
    if (flags.stats) {
        // User asked for stats: emit a dig-style stats footer using the
        // trace-mode `IP#53(name) (UDP)` SERVER formatting.
        std::string name(server_name);
        if (name.empty()) {
            name = std::string(server_ip);
        }
        out += fmt::format(";; Query time: {} msec\n", query_time.count());
        out += fmt::format(";; SERVER: {}#53({}) (UDP)\n", server_ip, name);
        out += fmt::format(";; MSG SIZE  rcvd: {}\n", sz);
    } else {
        out += format_trace_received_line(query_time, sz, server_ip, server_name);
    }
    // Blank line separator between hops (dig prints one after each Received).
    out += '\n';
    return out;
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
            // address and is mutually exclusive with a positional name/type.
            if (!opts.name.empty() || type_set) {
                result.error = "-x cannot be combined with a positional name or type";
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
        if (arg.starts_with('@')) {
            if (arg.size() == 1) {
                result.error = "empty server after '@'";
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
    return result;
}

} // namespace ag::adig
