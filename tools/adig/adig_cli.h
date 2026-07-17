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
#include <ctime>
#include <map>
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
// +class` (and `+nomultiline`). `+all`/`+noall` bulk-toggle the section-level
// members (the first seven below); the field-level flags (multiline, ttlid,
// cls, one_soa, ttl_units) are NOT part of `+all` (mirrors `dig` 9.20), so a
// `+nofoo` set before `+all` is preserved and `+noall +answer` still shows
// TTL/class.
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
    // Field/display-level flags (not toggled by `+all`). `one_soa` prints only
    // the first SOA of each section for `ANY`-style queries; `ttl_units` renders
    // the TTL as dig's human units (e.g. `5m`, `1h30m`).
    bool one_soa = false;
    bool ttl_units = false;
};

// An EDNS Client Subnet option (`+subnet=ADDR[/PREFIX]`, RFC 7871). `addr` is
// the raw IP literal; `src_prefix` is the source prefix length (0..32 for IPv4,
// 0..128 for IPv6). `enabled` is set by parse_args when `+subnet=` is given.
struct SubnetOpt {
    bool enabled = false;
    std::string addr;
    uint8_t src_prefix = 0;
};

// A generic EDNS option attached via `+ednsopt=CODE[:value]` (RFC 6891). `code`
// is the resolved EDNS option code (a mnemonic like `NSID`/`ECS`/`PAD`, or a
// decimal number, resolved at parse time by parse_ednsopt_code); `data` is the
// decoded hex payload (empty when no `:value` was given).
struct EdnsOption {
    uint16_t code = 0;
    std::vector<uint8_t> data;
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
    bool edns = true;         // +edns (default on) / +noedns — send an OPT RR (RFC 6891)
    uint8_t edns_version = 0; // +edns[=N] — EDNS version to advertise (0..255, default 0)
    bool dnssec = false;      // +dnssec / +do — sets the EDNS DO bit (forces an OPT RR)
    bool cd = false;          // +cdflag / +cd — sets the CD (Checking Disabled) bit
    bool reverse = false;     // set by `-x addr`: name is a reverse-lookup PTR
    bool print_query = false; // +qr — print the query packet before sending
    bool header_only = false; // +header-only — send a QDCOUNT=0 query (no question section), mirroring `dig`
    bool ad = true;           // +adflag (default on) — set the AD (Authenticated Data) bit
    bool cookie = true;       // +cookie (default on) — send a DNS COOKIE EDNS option (RFC 7873)
    SubnetOpt subnet;         // +subnet=ADDR[/PREFIX] (RFC 7871 ECS)
    // EDNS-layer extensions (+bufsize / +nsid / +padding / +ednsflags /
    // +ednsopt) and the opcode override (+opcode). +bufsize is 0 when unset
    // (apply_dns_flags then uses the default UDP payload size). These all imply
    // an OPT RR (so they force EDNS on even under +noedns, exactly like
    // +dnssec/+subnet); the opcode is applied last so a NOTIFY/UPDATE still
    // carries the requested EDNS options.
    uint16_t edns_bufsize = 0;          // +bufsize=N (EDNS UDP payload size)
    bool nsid = false;                  // +nsid (RFC 5001, EDNS option 3)
    uint16_t padding = 0;               // +padding=N (RFC 7830, EDNS option 12)
    std::optional<uint16_t> edns_flags; // +ednsflags=0xHH (raw EDNS Z-field bits)
    // +ednsopt=CODE[:hexvalue] (RFC 6891): generic EDNS options, attached in the
    // order given (repeatable); `+noednsopt` clears the list. Each entry is an
    // EDNS option, so it forces an OPT RR even under `+noedns`. The options are
    // appended after the named options (ECS/NSID) and before Padding, mirroring
    // `dig` (which builds the list after +nsid/+subnet and before +padding).
    std::vector<EdnsOption> ednsopts;
    std::optional<ldns_pkt_opcode> opcode; // +opcode=NAME (overwrite the opcode)
    std::optional<uint16_t> port;          // -p PORT (overwrite the plain-DNS port)
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
// `vc`->tcp, `do`->dnssec, `cd`->cdflag, `rd`/`rdflag`->recurse are recognized
// in addition to prefixes (`rd`/`rdflag` are not prefix-matchable since
// `recurse` does not start with `rd`).
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
// The EDNS-layer flags (+edns/+noedns, +dnssec DO bit, +cdflag, +subnet) are
// applied separately by apply_dns_flags() so they can be toggled independently.
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

// Encode a generic EDNS option as the wire TLV (option-code(2 BE) +
// option-length(2 BE) + option-data) that ldns writes verbatim into the OPT
// RR's RDATA. This is the shared building block for every EDNS option adig
// attaches (ECS, NSID, Padding, …), exposed so each option's encoding stays
// byte-exact and unit-testable without an event loop.
std::vector<uint8_t> encode_edns_option(uint16_t code, const uint8_t *data, size_t len);

// Resolve an `+ednsopt=CODE` argument to an EDNS option code (RFC 6891).
// Accepts a case-insensitive mnemonic mapped to its RFC code — mirroring
// `dig`'s `optnames` table (NSID->3, ECS->8, PAD/PADDING->12, COOKIE->10,
// EDE->15, KEEPALIVE->11, EXPIRE->9, CHAIN->13, KEY-TAG->14, CLIENT-TAG->16,
// SERVER-TAG->17, RC/REPORT-CHANNEL->18, ZONEVERSION->19, LLQ->1, UL->2,
// DAU->5, DHU->6, N3U->7, DEVICEID->26946) — or a decimal numeric code
// (0..65535). Returns nullopt for an unrecognized mnemonic / an out-of-range
// number. Exposed so the mnemonic resolution stays unit-testable.
std::optional<uint16_t> parse_ednsopt_code(std::string_view code);

// Decode a hexadecimal string (case-insensitive; ASCII whitespace ignored) to
// its raw bytes, the way `dig +ednsopt=CODE:value` decodes the option payload.
// Returns nullopt for non-hex characters or an odd number of hex digits
// (mirrors ISC's `isc_hex_decodestring`, which rejects both). Exposed so the
// hex decoding stays unit-testable.
std::optional<std::vector<uint8_t>> decode_hex_string(std::string_view hex);

// Resolve an `+opcode=NAME` argument to a DNS opcode. Accepts the standard
// names (case-insensitive: QUERY, IQUERY, STATUS, NOTIFY, UPDATE) and a raw
// numeric opcode (0..15). Returns nullopt for an unrecognized name / an
// out-of-range number.
std::optional<ldns_pkt_opcode> parse_opcode_name(std::string_view name);

// Format a TTL using `dig`'s human-readable units (+ttlunits): a value like
// `300` becomes `5m`, `5400` becomes `1h30m`, `86400` becomes `1d`. Each
// non-zero week/day/hour/minute/second unit is emitted in turn, with leading
// and trailing zero units suppressed (so 0 itself prints as `0`). Mirrors
// `dig 9.20` (verified: `dig +ttlunits` renders an 86400-second TTL as `1d`).
std::string format_dns_ttl_units(uint32_t ttl);

// Format a TTL using the verbose form dig puts in `+multiline` SOA comments:
// each non-zero week/day/hour/minute/second unit is spelled out in full
// (singular when N==1, plural otherwise), space-separated; trailing zero units
// are suppressed; a 0 TTL prints as `0 seconds`. Matches BIND's
// `dns_ttl_totext(num, true, true)` as called by `soa_6.c` for the SOA
// refresh/retry/expire/minimum comments (e.g. `; refresh (15 minutes)`,
// `; expire (1 week)`, `; refresh (2 hours 46 minutes 40 seconds)`). The TTL
// column value itself (e.g. `5m` from `+ttlunits`) is unaffected — this is
// only the verbose wording inside the SOA RDATA parenthetical.
std::string format_dns_ttl_verbose(uint32_t ttl);

// Format the response OPT-RDATA options as dig-compatible `; <NAME>: ...`
// lines (one per option), decoding the common ones (CLIENT-SUBNET per RFC
// 7871, NSID per RFC 5001, EDE per RFC 8914). Unknown options fall back to
// dig's generic `; \# N <hex>`. Each returned line already ends with `\n`.
// Exposed so the option-decoding stays unit-testable without a packet.
std::string format_edns_option_text(uint16_t code, const uint8_t *data, size_t len);

// Format `server` as dig's `;; SERVER:` value. For a plain IP / bare host it
// yields `host#port(host) (UDP)` (or `(TCP)` when `tcp` is true). adig's `+tcp`
// rewrite (apply_force_tcp) prefixes a bare host with `tcp://` (and rewrites
// `udp://`/`dns://` to `tcp://`) *before* formatting, so a leading plain-DNS
// scheme (`tcp://`/`udp://`/`dns://`, matched case-insensitively) is stripped
// here and the protocol is taken from the scheme (so `+tcp` renders `(TCP)`).
// Encrypted schemes (`tls://`, `https://`, `h3://`, `quic://`, `sdns://`,
// `system://`, …) are returned unchanged, mirroring `dig` (dig's SERVER
// formatting only applies to plain DNS). `port` is the `-p PORT` override; when
// unset the port is taken from an explicit `host:port` in `server`, else 53.
std::string format_dig_server(std::string_view server, std::optional<uint16_t> port, bool tcp);

// Format a wall-clock timestamp as dig's `WHEN:` value, e.g.
// `Thu Jul 16 17:11:43 EEST 2026`, using the local timezone. Returns an empty
// string when `when` is 0 so callers can omit the line (e.g. the `+qr` query
// echo has no answer time to report).
std::string format_dig_when(std::time_t when);

// Apply the EDNS-layer CLI flags to an already-built query packet. `+edns`
// (the default, opts.edns) attaches an OPT RR carrying the configured UDP
// payload size (+bufsize, default 4096) and the version from opts.edns_version;
// `+noedns` (opts.edns == false) suppresses it. `+dnssec` sets the DO bit and
// always forces an OPT RR (the DO bit lives in the OPT record, so it cannot be
// sent without EDNS even under `+noedns`, mirroring `dig`). `+cdflag` sets the
// CD bit. `+adflag` (default on) sets the AD (Authenticated Data) header bit.
// `+cookie` (default on) attaches a DNS COOKIE EDNS option (RFC 7873, a random
// 8-byte client cookie) — only when an OPT RR is present (so `+noedns`
// suppresses the cookie along with the OPT, matching `dig`). `+header-only`
// strips the question section (QDCOUNT=0), mirroring `dig +header-only`.
// `+subnet` attaches the ECS option and always forces an OPT RR (it is
// an EDNS option). `+nsid`, `+padding` and `+ednsflags` likewise attach their
// EDNS data / set the Z-field bits and force an OPT RR. `+ednsopt` appends its
// generic EDNS options after `+subnet`/`+nsid` and before `+padding` (matching
// `dig`'s build order) and likewise forces an OPT RR, since each entry is an
// EDNS option. `+opcode`, when set, is applied last via
// `ldns_pkt_set_opcode`. RD is not touched here; it is set at
// construction time by make_query().
void apply_dns_flags(ldns_pkt *pkt, const CliOptions &opts);

// A glue address extracted from a referral response's ADDITIONAL section, tagged
// with its address family so +trace can honor -4 (skip IPv6 glue).
struct GlueAddress {
    std::string address;
    bool ipv6 = false;
};

// Extract A/AAAA glue from a referral response's ADDITIONAL section, keyed by
// owner name (as ldns renders it: fully-qualified, with a trailing dot, matching
// the NS target names produced alongside in adig.cpp's extract_ns_names).
// Prefers A (IPv4) over AAAA (IPv6): when both are present for an owner the IPv4
// address wins (an A always overwrites any prior AAAA, and an AAAA is stored
// only when no A was seen for that owner). This prevents a later AAAA from
// displacing an earlier A, so +trace neither prefers IPv6 when IPv4 glue is
// present nor makes the chosen address depend on ADDITIONAL RR ordering. Exposed
// in the pure layer so the preference is unit-testable without an event loop.
std::map<std::string, GlueAddress> additional_glue(const ldns_pkt *pkt);

// Whether `glue` may be used to contact the next +trace hop given the -4
// (ipv4_only) flag. IPv6 glue is suppressed under -4 so a literal IPv6 address
// is never handed to trace_exchange() — which would otherwise connect to it
// regardless of the upstream factory's ipv6_available=false, since that flag
// only governs AAAA bootstrapping/resolution, not dialing a literal IPv6 peer.
// Mirrors the cmd_banner_enabled pattern of keeping a small decision rule
// unit-testable in the pure layer.
bool glue_address_usable(const GlueAddress &glue, bool ipv4_only);

// Format a DNS packet as dig-style text. Honors the per-section toggles in
// `flags` (comments, question, answer, authority, additional, stats) plus the
// field-level flags (multiline, ttlid, cls, one_soa, ttl_units).
// When `is_query` is true (the +qr query echo), the preamble says "Sending:"
// instead of "Got answer:" and the size line says "sent" rather than "rcvd".
// `query_time` populates the ";; Query time:" line, `server` populates the
// ";; SERVER:" line (already formatted as dig's `IP#port(host) (proto)` by the
// caller via format_dig_server), and `when` populates `;; WHEN:`; each may be
// left as zero / empty to omit the corresponding line.
std::string format_packet_dig(const ldns_pkt *pkt, const DisplayFlags &flags, bool is_query, Millis query_time,
        std::string_view server, std::time_t when = 0);

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

// Rewrite `server` so that `+tcp` takes effect for plain DNS: `udp://` and
// `dns://` schemes become `tcp://`, and a bare host (no `://`) is prefixed with
// `tcp://`. Encrypted schemes (tls://, https://, quic://, sdns://, system://,
// an explicit tcp://, ...) are left untouched. Mutates `server` in place.
// Exposed in the pure layer so the scheme rewrite (notably preserving the
// `://` separator) is unit-testable without an event loop.
void apply_force_tcp(std::string &server);

// Apply `-p PORT` to a plain-DNS server: when `port` is set and `server` has
// no scheme, the port is overridden — any explicit `host:port` is stripped first
// (only a single host/port colon is treated as a separator, so a bare IPv6
// literal — two or more colons — is left alone and not mis-split). Schemed
// upstreams are left untouched (dig's -p applies to plain DNS only). `+tcp`'s
// scheme-rewrite (apply_force_tcp) runs afterwards and preserves the port
// (`1.1.1.1:5353` -> `tcp://1.1.1.1:5353`). Mutates `server` in place; exposed
// in the pure layer so it is unit-testable without an event loop.
void apply_port(std::string &server, std::optional<uint16_t> port);

// Format one `dig +trace` hop as dig-compatible text. The body is produced by
// `format_packet_dig` with the standard stats block suppressed. The footer is
// then either:
//   - the trace-specific `;; Received <N> bytes from <ip>#53(<name>) in <ms> ms`
//     line (when `flags.stats` is off, the default in trace mode);
//   - a dig-style standard stats footer using `IP#53(name) (proto)` formatting
//     for `SERVER` (when `flags.stats` is on, e.g. via `+stats` / `+all`).
// `server_ip` is the IP literally contacted for this hop; `server_name` is its
// hostname if known (e.g. `a.root-servers.net`), or empty to repeat the IP.
// `tcp` selects the transport rendered in the stats footer's `(proto)` — true
// for `+tcp` (which forces `tcp://` hops in `run_trace`), false for the default
// UDP trace. A trailing blank line separates this hop from the next.
std::string format_trace_packet_dig(const ldns_pkt *pkt, const DisplayFlags &flags, Millis query_time,
        std::string_view server_ip, std::string_view server_name, bool tcp = false);

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
