# `adyg` command-line tool

`adyg` is a small `dig`-like DNS query command-line tool built directly on the
`upstream` library. It is a standalone executable (it does not link the full
DNS proxy) and is handy for ad-hoc DNS lookups and for exercising upstream
configurations during development.

See the main [README.md](../README.md) for an overview of the whole project,
and [DEVELOPMENT.md](../DEVELOPMENT.md) for general build and test workflow.

## Name

`adyg` reads like "адыг" in Cyrillic. The name was chosen just for fun: it is
kind of close to how some people in the company nicknamed AdGuard, and it is
also hard to pronounce properly.

## Building

```sh
make build_adyg
```

This produces the `adyg` executable in the CMake build directory of the active
preset, `cmake-build-clang-relwithdebinfo/tools/adyg/adyg` by default (i.e.
invoke it as `./cmake-build-clang-relwithdebinfo/tools/adyg/adyg`). It is
**not** installed onto `PATH` — invoke it by its full build path so the right
binary is used.

Release binaries for Linux (`x86_64`, `aarch64`, `armv7`, `mips`, `mipsel`),
macOS (universal) and Windows (`x86_64`, `i686`, `aarch64`) are built, signed
and attached to the GitHub Release by `.github/workflows/build-adyg.yml`.

The `+trace` option iterates the delegation chain from the root, seeding the
first hop from a `.` NS query to `@server` (mirroring `dig +trace`); if
`@server` is unreachable, it falls back to the IANA root hints checked into
the repo as `tools/adyg/root_servers.h`. Regenerate that header with
`make generate_root_hints` (requires network access).

## Usage

```text
adyg [@server] [-t type] [-x addr] name [type] [options]
```

Sends a DNS query to `server` for `name` (default RR type `A`) and prints the
reply. When `server` is omitted, `adyg` queries the system default DNS via the
upstream library's `SystemUpstream` (`system://`) on Apple/Android, falling
back to `1.1.1.1` on platforms where no system resolver is available.

The RR type may be given either positionally (`adyg name type`, mirroring
`dig`) or via the dig-compatible `-t TYPE` short option (`adyg -t TYPE name`).
Both forms are accepted in any position relative to `@server`, `name` and
the `+options`; the last one wins when both forms are given — matching
`dig example.com A -t AAAA`, which warns "extra type option" and queries
AAAA. `-t` is mutually exclusive with `-x` (which fixes the type to PTR).

### Server argument (`@server`)

The optional `@server` argument selects the upstream DNS server to query. It
is the substring after `@` (so `@1.1.1.1` ⟶ server `1.1.1.1`); the `@` is
the optional-position marker and does not form part of the server string.

`@server` may be placed anywhere in the argv stream relative to the
positional `name` / `type` and the `+options` — only one server may be given
(a second `@server` is an error, since multiple servers are not currently
supported). When omitted, the default is used (see [`Usage`](#usage) above).

`server` is handed verbatim to the `upstream` library, which accepts any of
the following forms:

| Server form | Protocol | Notes |
| --- | --- | --- |
| `1.1.1.1` | Plain DNS over UDP (default port 53) | Bare IPv4 / hostname |
| `1.1.1.1:53` | Plain DNS over UDP | IPv4 with explicit port |
| `[::1]:53` / `[::1]` | Plain DNS (IPv6 literal) | Brackets keep the IPv6 literal from being mis-split on `:` |
| `tcp://IP[:port]` | Plain DNS over TCP | `tcp://` forces TCP transport |
| `udp://IP[:port]` | Plain DNS over UDP | Synonym for the bare form (our `adyg` recognizes both) |
| `dns://IP[:port]` | Plain DNS over UDP | dig-compat scheme (rarely used) |
| `tls://host[:port]` | DNS-over-TLS (DoT) | Default port 853; the host part is verified against the TLS cert (so `tls://1.1.1.1` works because Cloudflare's cert carries the IP SAN; for self-signed setups use a `sdns://` stamp) |
| `https://host/path` | DNS-over-HTTPS (DoH) | Default port 443; the path is the DoH endpoint (commonly `/dns-query`) |
| `h3://host/path` | DNS-over-HTTP/3 | HTTP/3 (QUIC) variant of DoH |
| `quic://host[:port]` | DNS-over-QUIC (DoQ) | Default port 853 |
| `sdns://...` | Any of the above plus DNSCrypt | A [DNS Stamp](https://dnscrypt.info/stamps/) encodes scheme, address, port, hash and transport |
| `system://` | The OS-configured resolver (Apple/Android only) | Also the default when `@server` is omitted on those platforms |

A few things to keep in mind about `@server`:

- The scheme prefix (e.g. `tls://`) and the host are matched as a single
  argv token — write `@tls://1.1.1.1`, not `@ tls://1.1.1.1`.
- Scheme matching is case-insensitive (so `@TLS://1.1.1.1` is equivalent to
  the lowercase form).
- `-p PORT` overrides the port for plain-DNS forms (`@1.1.1.1`,
  `@tcp://1.1.1.1`, …); schemed upstreams ignore `-p` (their port is part
  of the URL). Use an explicit `host:port` for plain DNS or `+bootstrap=IP`
  for the GLUE resolver.
- `+tcp` rewrites a bare host / `udp://` / `dns://` form to `tcp://` so
  plain-DNS queries are sent over TCP. Encrypted schemes (`tls://`,
  `https://`, `quic://`, `sdns://`, `system://`) are left untouched.
- `+bootstrap=IP` selects the resolver used to look up the host portion of
  an encrypted upstream (e.g. to resolve `dns.adguard.com` in
  `tls://dns.adguard.com`). Defaults to `system://` on Apple/Android, and
  to nothing on other platforms (where a hostname-bearing scheme without
  `+bootstrap=` surfaces `AE_EMPTY_BOOTSTRAP`).

### `+trace`

Iterative resolution from the root, mirroring `dig +trace`. The first hop
queries `@server` for `.` NS records with the RD bit set; when `@server` is
omitted it defaults to the system resolver (`system://` on Apple/Android, else
`1.1.1.1`) — the same default as a non-trace query, since `dig +trace` always
starts by querying the configured resolver. Subsequent hops query each
delegating authoritative server directly (RD=0). Output is dig-compatible:

```text
adyg @1.1.1.1 example.com +trace
; <<>> adyg <version> <<>> @1.1.1.1 example.com +trace
;; global options: +cmd
.                       49625   IN      NS      c.root-servers.net.
... (root NS records)
;; Received 239 bytes from 1.1.1.1#53(1.1.1.1) in 7 ms

example.com.            81      IN      A       172.66.147.243
example.com.            81      IN      A       104.20.23.154
;; Received 72 bytes from 192.33.4.12#53(c.root-servers.net) in 10 ms
```

`+trace` collapses the per-hop display to plain RRs (no `;; Got answer:` /
`;; ->>HEADER<<-` / `;; QUESTION SECTION:` headers, no standard
`;; Query time:` / `;; SERVER:` / `;; MSG SIZE:` block) and ends each hop with
the trace-specific `;; Received <N> bytes from <ip>#<port>(<name>) in <ms> ms`
footer followed by a blank line. `<port>` is the actual peer port (extracted
from the seeded hop's `@server`, defaulting to `53` for the bare-glue iteration
hops), so `@1.1.1.1:5353 +trace` reports `1.1.1.1#5353(...)` rather than a
hardcoded `#53`. Re-enabling dig-style output is order-sensitive, exactly like
`dig`:

- `+trace +stats` swaps the `Received` footer for the standard
  `Query time` / `SERVER` (`IP#<port>(name) (proto)`) / `MSG SIZE` block, where
  `proto` is the hop transport — `UDP` by default, `TCP` under `+tcp` (which
  rewrites each hop to `tcp://`).
- `+trace +comments` re-enables the `;; Got answer:` header and section titles
  above the RRs.
- `+trace +all` enables every display flag (full per-hop output).
- A flag placed before `+trace` (e.g. `+comments +trace`) is overridden by the
  trace defaults; placing it after `+trace` (e.g. `+trace +comments`) keeps it
  on.

`+bootstrap=IP` selects the resolver used for glueless NS hostnames (when a
referral returns NS targets without glue). `+tcp` switches each per-hop query
to TCP.

`+trace` sets the EDNS DNSSEC OK (DO) bit, matching `dig +trace` (which
unconditionally enables `lookup->dnssec`). A later `+nodnssec` clears it
again; an earlier `+dnssec` is overridden by the trace default but can be
re-asserted after `+trace`.

### Other options

Notable options (each `dig`-compatible):

- `+short` — terse output (RDATA only)
- `+trace` — iterative resolution from the root (dig-compatible output; see
  [`+trace`](#trace) above)
- `+tcp` — use TCP for plain DNS
- `+timeout=N` — query timeout in seconds (default 5)
- `+recurse` / `+norecurse` — set or clear the RD bit (default on). `+rd` /
  `+rdflag` are dig aliases for `+recurse` (and `+nord` / `+nordflag` for its
  negation)
- `+edns[=N]` / `+noedns` — send an OPT RR (default on, matching `dig`). `+edns`
  is equivalent to `+edns=0`; `+edns=N` advertises EDNS version `N` (0..255).
  `+noedns` suppresses the default OPT RR. `+dnssec` (the DO bit), `+subnet`
  (the ECS option), `+nsid`, `+padding`, `+ednsflags` and `+ednsopt` still
  attach an OPT RR even under `+noedns`, since they live inside the OPT record
- `+dnssec` / `+do` — set the EDNS DO bit and a 4096-byte UDP payload
- `+cdflag` / `+cd` — set the CD (checking disabled) bit
- `+adflag` / `+noadflag` — set or clear the AD (Authenticated Data) bit
  (default on, matching `dig`). AD is a DNS header flag (not an EDNS option),
  so it is set even under `+noedns`
- `+cookie` / `+nocookie` — send or suppress a DNS COOKIE EDNS option (RFC 7873,
  default on, matching `dig`). The cookie is an 8-byte random client cookie,
  only attached when an OPT RR is present (so `+noedns` suppresses it too)
- `+subnet=ADDR[/PREFIX]` — send EDNS Client Subnet (RFC 7871)
- `+bufsize=N` — EDNS UDP payload size (default 4096)
- `+nsid` — send the EDNS NSID option (RFC 5001)
- `+padding=N` — send the EDNS Padding option, `N` zero bytes (RFC 7830)
- `+ednsflags=0xHH` — set raw EDNS header flags (Z) bits (decimal or `0x`-hex);
  `+noednsflags` clears them
- `+ednsopt=CODE[:value]` — send a generic EDNS option (RFC 6891), repeatable.
  `CODE` is a case-insensitive mnemonic (`NSID`, `ECS`, `PADDING`/`PAD`,
  `COOKIE`, `EDE`, `KEEPALIVE`, `EXPIRE`, `CHAIN`, `KEY-TAG`, `CLIENT-TAG`,
  `SERVER-TAG`, `REPORT-CHANNEL`/`RC`, `ZONEVERSION`, `LLQ`, `UL`/`UPDATE-LEASE`,
  `DAU`, `DHU`, `N3U`, `DEVICEID`) or a decimal number (0..65535); the optional
  `:value` is the option-data payload as a hex string (whitespace ignored). The
  options are appended after the named options (`+subnet`/`+nsid`) and before
  `+padding`, matching `dig`'s build order. `+noednsopt` clears the list (any
  value is ignored). Each entry forces an OPT RR, so it attaches even under
  `+noedns` (it is an EDNS option)
- The combined EDNS option blob (`+cookie`/`+subnet`/`+nsid`/`+ednsopt`/
  `+padding`) must fit the OPT record's 16-bit RDLEN (≤ 65535 bytes) and each
  option's data must fit its 16-bit option-length; adyg enforces this at parse
  time and reports a clear error otherwise (e.g. `+cookie +padding=65535` is
  rejected instead of producing a malformed packet)
- `+opcode=NAME` — set the opcode (`QUERY`/`IQUERY`/`STATUS`/`NOTIFY`/`UPDATE`,
  or a numeric opcode); `+noopcode` clears the override
- `+qr` — print the query packet before sending
- `+header-only` — send a header-only query (QDCOUNT=0, no question section),
  mirroring `dig +header-only` which probes server capabilities without sending
  a question record
- `+aaflag` / `+defname` / `+showsearch` — accepted as dig-compatibility no-ops
  (they relate to resolver behaviors adyg does not implement), so common `dig`
  scripts do not error
- `-4` — use IPv4 only (suppress IPv6)
- `-t TYPE` — dig short-form RR type (A/AAAA/MX/TXT/ANY/...); equivalent to the
  positional `name type` form (see [Usage](#usage))
- `-p PORT` — override the plain-DNS port (default 53)
- `-x addr` — reverse lookup (PTR for the given IPv4/IPv6 address); mutually
  exclusive with `-t` and the positional `type`
- `-v`, `--version` — print version and exit

Display flags (`+cmd`, `+comments`, `+question`, `+answer`, `+authority`,
`+additional`, `+stats`, `+ttlid`, `+class`) toggle per-section output and
each supports a `+no` prefix; `+all` / `+noall` toggle the section-level flags
at once (the field-level flags below are not part of `+all`). Additional
dig-compatible display flags:

- `+multiline` — render long records inside a `( ... )` block with aligned
  columns and a four-tab continuation indent. The column layout is byte-exact
  with `dig` (three-branch tab-stop table from `dig.c`: default 24/32/40/48,
  `+nottlid` or `+noclass` shift to 24/24/32/40, `+nottlid +noclass` to
  24/24/24/32; the QUESTION section always preserves an empty TTL column).
  SOA records use `dig`'s `soa_6.c` multiline format (`%-10lu` per field,
  `; serial` / `; refresh (1 hour)` verbose-TTL comments, `(` and `)` on
  their own lines). Only `DS`, `KEY`, `RRSIG`, and `SSHFP` records are
  candidates for `( ... )` wrapping; `TXT` and other types are never wrapped
- `+ttlunits` — show TTLs as dig's human units (e.g. `5m`, `1h30m`, `1d`)
- `+onesoa` — print only the first SOA of the response (useful for `ANY`)

The standard stats block is dig-compatible: `;; Query time:`,
`;; SERVER: <ip>#<port>(<host>) (UDP|TCP)`, `;; WHEN: <date>` and
`;; MSG SIZE  rcvd: <n>` (the `WHEN:` and dig-formatted `SERVER:` lines appear
on real responses; the `+qr` query echo omits them and labels the size
`;; QUERY SIZE: <n>` instead of `;; MSG SIZE  sent:`).

## Examples

```sh
adyg example.com
adyg @1.0.0.1 example.com MX
# -t is the dig short form for the type, equivalent to the positional above:
adyg -t MX @1.0.0.1 example.com
# the user's reported case from the issue — a plain `-t TYPE` form on DoT:
adyg -t mx serveroid.com @tls://1.1.1.1
adyg @tls://dns.adguard.com example.com +short
adyg @sdns://... example.com +trace +bootstrap=1.1.1.1
adyg @1.1.1.1 example.com +dnssec +recurse
adyg @1.1.1.1 example.com +noedns
adyg @1.1.1.1 example.com +edns=1
adyg -x 8.8.8.8
adyg @1.1.1.1 example.com +subnet=1.2.3.4/24
adyg @1.1.1.1 example.com +ednsopt=nsid
adyg @1.1.1.1 example.com +ednsopt=10:01020304
adyg @1.1.1.1 example.com +noall +answer
```

Command-line parsing is implemented in
[`tools/adyg/adyg_cli.cpp`](../tools/adyg/adyg_cli.cpp) (interface:
[`tools/adyg/adyg_cli.h`](../tools/adyg/adyg_cli.h)). The pure logic is split by
concern across three translation units, all sharing the `adyg_cli.h` interface:
argument parsing & CLI transforms (`adyg_cli.cpp`), the EDNS/IP helpers
(`adyg_cli_edns.cpp`) and the packet construction & dig-compatible formatting
(`adyg_cli_packet.cpp`). The few internal helpers shared across the units live
in `adyg_cli_internal.h` (not part of the public interface).
