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
  `Query time` / `SERVER` (`IP#53(name) (UDP)`) / `MSG SIZE` block.
- `+trace +comments` re-enables the `;; Got answer:` header and section titles
  above the RRs.
- `+trace +all` enables every display flag (full per-hop output).
- A flag placed before `+trace` (e.g. `+comments +trace`) is overridden by the
  trace defaults; placing it after `+trace` (e.g. `+trace +comments`) keeps it
  on.

`+bootstrap=IP` selects the resolver used for glueless NS hostnames (when a
referral returns NS targets without glue). `+tcp` switches each per-hop query
to TCP.

### Other options

Notable options (each `dig`-compatible):

- `+short` — terse output (RDATA only)
- `+trace` — iterative resolution from the root (dig-compatible output; see
  [`+trace`](#trace) above)
- `+tcp` — use TCP for plain DNS
- `+timeout=N` — query timeout in seconds (default 5)
- `+recurse` / `+norecurse` — set or clear the RD bit (default on)
- `+dnssec` / `+do` — set the EDNS DO bit and a 4096-byte UDP payload
- `+cdflag` / `+cd` — set the CD (checking disabled) bit
- `+subnet=ADDR[/PREFIX]` — send EDNS Client Subnet (RFC 7871)
- `+qr` — print the query packet before sending
- `-4` — use IPv4 only (suppress IPv6)
- `-x addr` — reverse lookup (PTR for the given IPv4/IPv6 address)
- `-v`, `--version` — print version and exit

Display flags (`+cmd`, `+comments`, `+question`, `+answer`, `+authority`,
`+additional`, `+stats`, `+ttlid`, `+class`) toggle per-section output and
each supports a `+no` prefix; `+all` / `+noall` toggle all sections at once.

## Examples

```sh
adig example.com
adig @1.0.0.1 example.com MX
adig @tls://dns.adguard.com example.com +short
adig @sdns://... example.com +trace +bootstrap=1.1.1.1
adig @1.1.1.1 example.com +dnssec +recurse
adig -x 8.8.8.8
adig @1.1.1.1 example.com +subnet=1.2.3.4/24
adig @1.1.1.1 example.com +noall +answer
```

Command-line parsing is implemented in
[`tools/adig/adig_cli.cpp`](../tools/adig/adig_cli.cpp) (interface:
[`tools/adig/adig_cli.h`](../tools/adig/adig_cli.h)).
