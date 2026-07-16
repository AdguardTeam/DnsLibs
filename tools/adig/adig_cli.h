// adig_cli — pure (event-loop-free) command-line logic for the adig tool.
//
// This header declares the parts of adig's argument handling that do not depend
// on the upstream library's event loop, so they can be unit-tested in
// isolation. The coroutine-based query/trace logic lives in adig.cpp.
//
// See docs/adig.md for the authoritative description of adig's command-line
// interface.

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <ldns/ldns.h>

#include "common/defs.h"
#include "dns/common/dns_defs.h"

namespace ag::adig {

// ldns smart-pointer alias (UniquePtr<ldns_pkt, &ldns_pkt_free>) lives in the
// ag::dns namespace; re-expose it here so the pure layer can name it directly.
using ag::dns::ldns_pkt_ptr;

// Default query timeout (5 seconds), matching the upstream library default.
constexpr Millis DEFAULT_TIMEOUT{5000};

// Fallback server used when no @server is given on platforms where the upstream
// module has no system resolver (i.e. not Apple/Android). Public so adig.cpp's
// default_server() can reference it.
constexpr std::string_view DEFAULT_SERVER = "1.1.1.1";

// Toggles for dig-compatible packet display. Defaults match `dig`'s defaults:
// `+cmd +comments +question +answer +authority +additional +stats +ttlid
// +class` (and `+nomultiline`). `+all`/`+noall` bulk-toggle every member.
struct DisplayFlags {
    bool cmd = true;
    bool comments = true;
    bool question = true;
    bool answer = true;
    bool authority = true;
    bool additional = true;
    bool stats = true;
    bool multiline = false;
    bool ttlid = true;
    bool cls = true;
};

// An EDNS Client Subnet option (`+subnet=ADDR[/PREFIX]`, RFC 7871). `addr` is
// the raw IP literal; `src_prefix` is the source prefix length (0..32 for IPv4,
// 0..128 for IPv6). `enabled` is set by parse_args when `+subnet=` is given.
struct SubnetOpt {
    bool enabled = false;
    std::string addr;
    uint8_t src_prefix = 0;
};

// Command-line options for adig. Populated by parse_args().
struct CliOptions {
    // Empty when no @server was given; main() fills it with the system default
    // DNS (see default_server in adig.cpp — system:// on Apple/Android, else
    // DEFAULT_SERVER) before any query is sent.
    std::string server;
    std::string name;
    ldns_rr_type rr_type = LDNS_RR_TYPE_A;
    std::vector<std::string> bootstrap;
    Millis timeout = DEFAULT_TIMEOUT;
    bool short_output = false;
    bool force_tcp = false;
    bool trace = false;
    bool ipv4_only = false;   // -4: suppress IPv6 bootstrap (sets ipv6_available=false)
    bool recurse = true;      // +recurse (default on) / +norecurse — sets the RD bit
    bool dnssec = false;      // +dnssec / +do — sets the EDNS DO bit (and 4096 UDP size)
    bool cd = false;          // +cdflag / +cd — sets the CD (Checking Disabled) bit
    bool reverse = false;     // set by `-x addr`: name is a reverse-lookup PTR
    bool print_query = false; // +qr — print the query packet before sending
    SubnetOpt subnet;         // +subnet=ADDR[/PREFIX] (RFC 7871 ECS)
    DisplayFlags display;
};

// Result of resolving a `+option` keyword against adig's keyword table.
// `canonical` is the resolved canonical option name on success; `error` is
// non-empty (and `canonical` empty) when the keyword is unknown or its prefix
// is ambiguous.
struct KeywordMatch {
    std::string canonical;
    std::string error;
};

// Resolve a `+option` keyword (as typed, without the leading `+` and without a
// `no` prefix) to its canonical name. Matching is dig-style: an exact canonical
// or explicit-alias match wins; otherwise an unambiguous canonical prefix
// matches; multiple prefix matches are reported as ambiguous. The bare aliases
// `vc`->tcp are recognized in addition to prefixes.
KeywordMatch match_plus_keyword(std::string_view key);

// Build the in-addr.arpa / ip6.arpa reverse-lookup name for an IPv4 or IPv6
// address literal. Returns nullopt for anything that is not a valid address
// (the input is validated by round-tripping it through ldns's A/AAA rdf
// parser). Examples:
//   "1.2.3.4" -> "4.3.2.1.in-addr.arpa."
//   "::1"     -> "1.0.0.0...0.0.ip6.arpa." (32 reversed nibbles)
std::optional<std::string> make_reverse_name(std::string_view addr);

// Build a DNS query packet for `name`/`type`. When `recurse` is false the RD
// flag is cleared (used by `+trace` to query authoritative servers directly).
// The EDNS-layer flags (+dnssec DO bit, +cdflag, +subnet) are applied
// separately by apply_dns_flags() so they can be toggled independently.
ldns_pkt_ptr make_query(const std::string &name, ldns_rr_type type, bool recurse);

// Encode the EDNS Client Subnet option (RFC 7871, option code 8) as the raw
// TLV bytes that form the OPT RR's RDATA. The address is parsed as IPv4 (family
// 1) or IPv6 (family 2); `src_prefix` source-prefix bits are carried, the
// address is zero-padded to a byte boundary, and bits past the prefix in the
// last byte are cleared. Returns an empty vector when `addr` is not a valid IP
// literal or `src_prefix` exceeds the address family's maximum. The full TLV is
// returned (code + length + option-data) because that is exactly what ldns
// stores in the packet's EDNS data and writes verbatim as OPT RDATA.
std::vector<uint8_t> encode_ecs_option(std::string_view addr, uint8_t src_prefix);

// Apply the EDNS-layer CLI flags to an already-built query packet: the DO bit
// and a 4096-byte EDNS UDP payload size when `opts.dnssec` is set (RFC 3225),
// the CD bit when `opts.cd` is set, and the ECS option when `opts.subnet` is
// set. RD is not touched here; it is set at construction time by make_query().
void apply_dns_flags(ldns_pkt *pkt, const CliOptions &opts);

// Format a DNS packet as dig-style text. Honors the per-section toggles in
// `flags` (comments, question, answer, authority, additional, stats). When
// `is_query` is true (the +qr query echo), the preamble says "Sending:"
// instead of "Got answer:" and the size line says "sent" rather than "rcvd".
// `query_time` populates the ";; Query time:" line and `server` populates the
// ";; SERVER:" line when `flags.stats` is on; either may be left as zero /
// empty to omit the corresponding line.
std::string format_packet_dig(
        const ldns_pkt *pkt, const DisplayFlags &flags, bool is_query, Millis query_time, std::string_view server);

// Apply `dig +trace`'s display-flag defaults to `flags`: turn off `comments`,
// `question` and `stats` (so only the answer/authority/additional RRs are
// printed, wrapped in the trace-specific "Received ... bytes from ... " footer
// produced by `format_trace_packet_dig`). Called from `parse_args` when the
// `+trace` keyword is matched; flags modified after that (e.g. a later
// `+comments` / `+stats` / `+all`) still take effect, mirroring dig's
// order-sensitive precedence.
void apply_trace_display_defaults(DisplayFlags &flags);

// Whether the dig-style `; <<>> adig ... <<>>` / `;; global options: +cmd`
// banner should be printed. Mirrors `dig`: the banner is gated on `+cmd`, but
// `+short` suppresses it unconditionally (a later `+cmd` does not bring it
// back), so `+short` always yields RDATA-only output. Public so main() can
// delegate the decision and the rule remains unit-testable without an event
// loop.
bool cmd_banner_enabled(const CliOptions &opts);

// Format one `dig +trace` hop as dig-compatible text. The body is produced by
// `format_packet_dig` with the standard stats block suppressed. The footer is
// then either:
//   - the trace-specific `;; Received <N> bytes from <ip>#53(<name>) in <ms> ms`
//     line (when `flags.stats` is off, the default in trace mode);
//   - a dig-style standard stats footer using `IP#53(name) (UDP)` formatting
//     for `SERVER` (when `flags.stats` is on, e.g. via `+stats` / `+all`).
// `server_ip` is the IP literally contacted for this hop; `server_name` is its
// hostname if known (e.g. `a.root-servers.net`), or empty to repeat the IP.
// A trailing blank line separates this hop from the next.
std::string format_trace_packet_dig(const ldns_pkt *pkt, const DisplayFlags &flags, Millis query_time,
        std::string_view server_ip, std::string_view server_name);

// Format the dig-style "Received ... bytes from ... in ... ms" line emitted at
// the end of every `dig +trace` hop when `stats` is off. Exposed so the trace
// driver and tests can build it directly without going through
// `format_trace_packet_dig`'s full body. When `server_name` is empty the IP is
// repeated (mirroring `dig` when the peer has no reverse-DNS name available).
std::string format_trace_received_line(
        Millis query_time, size_t bytes, std::string_view server_ip, std::string_view server_name);

// Result of parsing the command line. `error` is empty on success and carries a
// human-readable message (without an "Error: " prefix) on failure. When
// `help_requested` is set the caller should print usage and exit 0; when
// `version_requested` is set it should print the version and exit 0; `opts` is
// left at its default in either of those cases.
struct ParseResult {
    bool help_requested = false;
    bool version_requested = false;
    std::string error;
    CliOptions opts;
};

// Parse adig command-line arguments into a CliOptions. Does not print to stderr
// nor exit; the caller is responsible for reporting `error` (prefixed with
// "Error: ") and for honoring `help_requested`.
ParseResult parse_args(int argc, char *argv[]);

} // namespace ag::adig
