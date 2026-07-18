// adyg_cli — internal helpers shared across the adyg_cli*.cpp translation units.
//
// This header is NOT part of the public interface (adyg_cli.h); it exposes the
// few file-local helpers that more than one split translation unit needs, so the
// pure CLI layer could be split by concern without duplicating IP-parsing logic.
// Include only from adyg_cli*.cpp.

#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string_view>

namespace ag::adyg {

// A parsed IPv4/IPv6 literal: its EDNS family code (1 / 2), the raw address
// bytes (zero-padded to 16), and the number of significant bytes (4 / 16).
// Used by make_reverse_name (reverse-DNS name), encode_ecs_option (ECS option)
// and parse_args (bare +subnet=ADDR default-prefix family detection), so the
// IP-parsing logic lives in exactly one place.
struct ParsedAddr {
    uint16_t family = 0;             // 1 = IPv4, 2 = IPv6
    std::array<uint8_t, 16> bytes{}; // first `len` bytes hold the address
    size_t len = 0;                  // 4 for IPv4, 16 for IPv6
};

// Parse an IPv4/IPv6 literal into its EDNS family code (1 / 2) and address
// bytes. Returns nullopt for anything that is not a valid address literal.
std::optional<ParsedAddr> parse_ip_addr(std::string_view addr);

// Try to split a trailing `host:port` from `host`. On success shortens `host` to
// the host portion (a view into the original buffer) and returns the port;
// returns nullopt (leaving `host` unchanged) when `host` has no `host:port` to
// split. Only a single colon is treated as a host/port separator, so a bare
// IPv6 literal (`::1`, `fe80::1`, … — two or more colons) is left untouched
// and is not mis-split on one of its own colons. A non-numeric or out-of-range
// (0 or >65535) port suffix is likewise not treated as a port. This supersedes
// the earlier dot-guard, which — by requiring a dot — also skipped dot-less
// hostnames carrying an explicit port (e.g. `localhost:53`).
//
// The bracketed IPv6 literal form `[v6]:port` (and a bare `[v6]`) is handled
// explicitly: the port candidate is the `:port` right after the closing
// bracket, and on success `host` keeps the brackets (`[v6]`) so the result
// stays an unambiguous IPv6 literal for callers that pass it on (apply_port
// re-appends the port as `[v6]:<port>`; format_dig_server strips the brackets
// for dig display). Without this the bracketed form has 2+ colons and would be
// refused by the single-colon path — the documented `@server` forms
// `[::1]:53` / `[::1]` in docs/adyg.md would then mis-compose with `-p` /
// `format_dig_server`.
std::optional<uint16_t> split_plain_host_port(std::string_view &host);

} // namespace ag::adyg
