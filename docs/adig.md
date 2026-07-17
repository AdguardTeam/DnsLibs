# `adig` command-line tool

`adig` is a small `dig`-like DNS query command-line tool built directly on the
`upstream` library. It is a standalone executable (it does not link the full
DNS proxy) and is handy for ad-hoc DNS lookups and for exercising upstream
configurations during development.

See the main [README.md](../README.md) for an overview of the whole project,
and [DEVELOPMENT.md](../DEVELOPMENT.md) for general build and test workflow.

## Supported protocols

The `@server` argument may be any address scheme supported by the `upstream`
library:

| Server form | Protocol |
| --- | --- |
| `1.1.1.1` / `1.1.1.1:53` | Plain DNS over UDP |
| `tcp://IP` | Plain DNS over TCP |
| `tls://host` | DNS-over-TLS (DoT) |
| `https://host/…` | DNS-over-HTTPS (DoH) |
| `quic://host` | DNS-over-QUIC (DoQ) |
| `sdns://…` | A DNS Stamp (any of the above, plus DNSCrypt) |
| `system://` | The OS-configured resolver (Apple/Android only); also the default when `@server` is omitted on those platforms |

## Building

```sh
make build_adig
```

This produces the `adig` executable in the CMake build directory. The `+trace`
option iterates the delegation chain from the root, seeding the first hop from
a `.` NS query to `@server` (mirroring `dig +trace`); if `@server` is
unreachable, it falls back to the IANA root hints checked into the repo as
`tools/adig/root_servers.h`. Regenerate that header with
`make generate_root_hints` (requires network access).

## Usage

```text
adig [@server] name [type] [options]
```

Sends a DNS query to `server` for `name` (default RR type `A`) and prints the
reply. When `server` is omitted, `adig` queries the system default DNS via the
upstream library's `SystemUpstream` (`system://`) on Apple/Android, falling
back to `1.1.1.1` on platforms where no system resolver is available.

### `+trace`

Iterative resolution from the root, mirroring `dig +trace`. The first hop
queries `@server` for `.` NS records with the RD bit set; when `@server` is
omitted it defaults to the system resolver (`system://` on Apple/Android, else
`1.1.1.1`) — the same default as a non-trace query, since `dig +trace` always
starts by querying the configured resolver. Subsequent hops query each
delegating authoritative server directly (RD=0). Output is dig-compatible:

```text
adig @1.1.1.1 example.com +trace
; <<>> adig <version> <<>> @1.1.1.1 example.com +trace
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
the trace-specific `;; Received <N> bytes from <ip>#53(<name>) in <ms> ms`
footer followed by a blank line. Re-enabling dig-style output is
order-sensitive, exactly like `dig`:

- `+trace +stats` swaps the `Received` footer for the standard
  `Query time` / `SERVER` (`IP#53(name) (proto)`) / `MSG SIZE` block, where
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
  option's data must fit its 16-bit option-length; adig enforces this at parse
  time and reports a clear error otherwise (e.g. `+cookie +padding=65535` is
  rejected instead of producing a malformed packet)
- `+opcode=NAME` — set the opcode (`QUERY`/`IQUERY`/`STATUS`/`NOTIFY`/`UPDATE`,
  or a numeric opcode); `+noopcode` clears the override
- `+qr` — print the query packet before sending
- `+header-only` — send a header-only query (QDCOUNT=0, no question section),
  mirroring `dig +header-only` which probes server capabilities without sending
  a question record
- `+aaflag` / `+defname` / `+showsearch` — accepted as dig-compatibility no-ops
  (they relate to resolver behaviors adig does not implement), so common `dig`
  scripts do not error
- `-4` — use IPv4 only (suppress IPv6)
- `-p PORT` — override the plain-DNS port (default 53)
- `-x addr` — reverse lookup (PTR for the given IPv4/IPv6 address)
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
adig example.com
adig @1.0.0.1 example.com MX
adig @tls://dns.adguard.com example.com +short
adig @sdns://... example.com +trace +bootstrap=1.1.1.1
adig @1.1.1.1 example.com +dnssec +recurse
adig @1.1.1.1 example.com +noedns
adig @1.1.1.1 example.com +edns=1
adig -x 8.8.8.8
adig @1.1.1.1 example.com +subnet=1.2.3.4/24
adig @1.1.1.1 example.com +ednsopt=nsid
adig @1.1.1.1 example.com +ednsopt=10:01020304
adig @1.1.1.1 example.com +noall +answer
```

Command-line parsing is implemented in
[`tools/adig/adig_cli.cpp`](../tools/adig/adig_cli.cpp) (interface:
[`tools/adig/adig_cli.h`](../tools/adig/adig_cli.h)). The pure logic is split by
concern across three translation units, all sharing the `adig_cli.h` interface:
argument parsing & CLI transforms (`adig_cli.cpp`), the EDNS/IP helpers
(`adig_cli_edns.cpp`) and the packet construction & dig-compatible formatting
(`adig_cli_packet.cpp`). The few internal helpers shared across the units live
in `adig_cli_internal.h` (not part of the public interface).
