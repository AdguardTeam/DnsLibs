// adyg — a small dig-like DNS query command-line tool built on the upstream
// library.
//
// Usage, options, and examples are documented in docs/adyg.md. See README.md
// for general build instructions.
//

#include <chrono>
#include <cstdio>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <fmt/format.h>
#include <ldns/ldns.h>

#include "adyg_cli.h"
#include "common/coro.h"
#include "common/defs.h"
#include "dns/common/dns_defs.h"
#include "dns/common/event_loop.h"
#include "dns/common/version.h"
#include "dns/net/application_verifier.h"
#include "dns/net/default_verifier.h"
#include "dns/net/socket.h"
#include "dns/upstream/upstream.h"
#include "root_servers.h"

namespace {

using ag::AllocatedPtr;
using ag::Millis;
using ag::coro::Task;
using ag::coro::to_future;
using ag::dns::CertificateVerifier;
using ag::dns::DefaultVerifier;
using ag::dns::EventLoop;
using ag::dns::EventLoopPtr;
using ag::dns::ldns_pkt_ptr;
using ag::dns::SocketFactory;
using ag::dns::UpstreamFactory;
using ag::dns::UpstreamOptions;
using ag::dns::UpstreamPtr;

using namespace ag::adyg;

constexpr size_t MAX_TRACE_ITERATIONS = 20;

struct QueryOutcome {
    std::string error;
    ldns_pkt_ptr reply;
    Millis query_time{};
};

struct TraceOutcome {
    std::string error;
};

int print_usage(const char *prog) {
    fmt::print(stderr,
            "Usage: {} [@server] [-t type] [-x addr] name [type] [options]\n"
            "\n"
            "Send a DNS query to a server and print the response.\n"
            "\n"
            "The RR type may be given either positionally (`name type`) or via\n"
            "-t TYPE; both forms are dig-compatible.\n"
            "\n"
            "Options:\n"
            "  +short            terse output (RDATA only)\n"
            "  +tcp              use TCP for plain DNS\n"
            "  +timeout=N        query timeout in seconds (default 5)\n"
            "  +trace            iterative resolution from the root servers\n"
            "  +bootstrap=IP     bootstrap server to resolve the server name (repeatable)\n"
            "                    (defaults to the system resolver when omitted)\n"
            "  +recurse / +rd    set the RD (recursion desired) bit (default)\n"
            "  +norecurse / +nord  clear the RD bit\n"
            "  +edns[=N]         send an OPT RR, optionally with EDNS version N (default on)\n"
            "  +noedns           do not send an OPT RR\n"
            "  +dnssec / +do     set the EDNS DO bit (request DNSSEC records)\n"
            "  +cdflag / +cd     set the CD (checking disabled) bit\n"
            "  +subnet=ADDR[/P]  send EDNS Client Subnet (RFC 7871)\n"
            "  +bufsize=N        EDNS UDP payload size (default 4096)\n"
            "  +nsid             send EDNS NSID option (RFC 5001)\n"
            "  +padding=N        send EDNS Padding option, N zero bytes (RFC 7830)\n"
            "  +ednsflags=0xHH   set raw EDNS header flags (Z) bits\n"
            "  +ednsopt=CODE[:v] send a generic EDNS option (RFC 6891); CODE is a\n"
            "                    mnemonic (NSID/ECS/PAD/COOKIE/...) or a decimal code,\n"
            "                    :v is a hex payload (repeatable; +noednsopt clears)\n"
            "  +opcode=NAME      set the opcode (QUERY/IQUERY/STATUS/NOTIFY/UPDATE)\n"
            "  +qr               print the query packet before sending\n"
            "  +adflag / +noadflag  set/clear the AD (Authenticated Data) bit (default on)\n"
            "  +cookie / +nocookie  send/suppress a DNS COOKIE EDNS option (RFC 7873, default on)\n"
            "  +aaflag +defname +showsearch  accepted (dig-compat no-ops)\n"
            "  -4                use IPv4 only (suppress IPv6)\n"
            "  -p PORT           override the plain-DNS port (default 53)\n"
            "  -t TYPE           RR type mnemonic (A/AAAA/MX/TXT/ANY/...; dig short form,\n"
            "                    equivalent to the positional `name type` argument)\n"
            "  -x addr           reverse lookup (PTR for IPv4/IPv6 address)\n"
            "  -h, --help        print this help and exit\n"
            "  -v, --version     print version and exit\n"
            "\n"
            "Display flags (dig-compatible, each supports +no prefix):\n"
            "  +cmd +comments +question +answer +authority +additional +stats\n"
            "  +all / +noall     toggle all sections at once\n"
            "  +ttlid / +class   show/hide TTL / class in RRs\n"
            "  +multiline        wrap long records into `( ... )` with aligned columns\n"
            "  +ttlunits         show TTL as dig's human units (e.g. 5m, 1h30m)\n"
            "  +header-only      send a header-only query (QDCOUNT=0, no question)\n"
            "  +onesoa           print only the first SOA of the response\n"
            "\n"
            "Server may be a plain IP, tcp://IP, tls://host, https://host/path, "
            "quic://host, sdns://... or system://\n"
            "Defaults: server=system DNS (system://, fallback 1.1.1.1), type=A\n",
            prog);
    return 0;
}

std::unique_ptr<CertificateVerifier> make_verifier() {
#ifndef _WIN32
    return std::make_unique<DefaultVerifier>();
#else
    return std::make_unique<ag::dns::ApplicationVerifier>([](const ag::dns::CertificateVerificationEvent &) {
        return std::nullopt;
    });
#endif
}

// Returns the bootstrap servers to use. When the user did not pass any
// `+bootstrap=IP`, fall back to the system resolver (`system://`) so that
// hostnames in encrypted upstream addresses (e.g. `tls://dns.adguard.com`)
// can be resolved without making the user supply bootstrap IPs explicitly.
// Note: `system://` upstreams are only available on Apple/Android; on other
// platforms an empty bootstrap list is returned and the error surfaces from
// upstream init (AE_EMPTY_BOOTSTRAP).
std::vector<std::string> effective_bootstrap(const std::vector<std::string> &bootstrap) {
#if defined(__APPLE__) || defined(__ANDROID__)
    if (bootstrap.empty()) {
        // Matches SystemUpstream::SYSTEM_SCHEME (upstream/upstream_system.h).
        return {"system://"};
    }
#else
    (void) bootstrap;
#endif
    return bootstrap;
}

// Returns the server to query when the user did not pass @server. Reuses the
// upstream module's system DNS functionality (SystemUpstream, scheme
// "system://") on the platforms where it is available, mirroring `dig` which
// queries the OS-configured resolver by default. On platforms where the
// upstream library has no system resolver, fall back to DEFAULT_SERVER. Applied
// for every code path, including +trace: run_trace() seeds its first hop (`.`
// NS) from opts.server and only falls back to the root hints if that hop yields
// no servers.
std::string default_server() {
#if defined(__APPLE__) || defined(__ANDROID__)
    // Matches SystemUpstream::SYSTEM_SCHEME (upstream/upstream_system.h). The
    // upstream factory recognizes this scheme and creates a SystemUpstream that
    // resolves via the OS resolver (DNSService on Apple, android_res_* on
    // Android).
    return "system://";
#else
    return std::string(DEFAULT_SERVER);
#endif
}

void print_packet_dig(const ldns_pkt *pkt, const CliOptions &opts, bool is_query, Millis query_time) {
    std::string server;
    std::time_t when = 0;
    if (!is_query) {
        // dig formats SERVER as `IP#port(host) (proto)` for plain DNS; for
        // schemed upstreams the raw address is shown. `when` populates the
        // `;; WHEN:` line (a zero time omits it, matching the +qr query echo).
        server = format_dig_server(opts.server, opts.port, opts.force_tcp);
        when = std::time(nullptr);
    }
    std::string text = format_packet_dig(pkt, opts.display, is_query, query_time, server, when);
    std::fputs(text.c_str(), stdout);
    // Keep the display in sync with any stderr error that follows (e.g. the
    // "exchange failed" path) so a merged stdout+stderr stream shows them in
    // the right order, mirroring `dig` (banner + answer, then errors).
    std::fflush(stdout);
}

// One server queried during a `+trace` pass. `ip` is the address actually
// contacted (a bare IP for the iteration hops; `opts.server` verbatim for the
// initial seeded hop to the user's resolver — possibly carrying a `host:port`
// or a plain-DNS scheme, both of which `split_trace_server_addr` strips when
// formatting the footer). `name` is the hostname shown inside the `(NAME)` of
// dig's `Received ... bytes from IP#<port>(NAME)` footer; empty falls back to
// the bare host extracted from `ip` (mirroring `dig` when the peer has no
// resolvable name — and avoiding the raw `opts.server` being echoed into the
// parens, where it would otherwise leak a stale `:port` / scheme prefix).
struct TraceServer {
    std::string ip;
    std::string name;
};

// Per-hop trace output. Builds a dig-compatible body (RRs from the active
// display sections) followed by the trace-specific footer:
//   - default (`+stats` off, the trace mode default): the
//     `;; Received N bytes from IP#<port>(name) in Y ms` line;
//   - when `+stats` is on: the standard `Query time` / `SERVER`
//     (formatted `IP#<port>(name) (proto)`, where proto is TCP under `+tcp` and
//     UDP otherwise) / `MSG SIZE` block.
// `<port>` is extracted from `server.ip` (`#53` by default for the iteration
// hops, which carry bare glue A records). A trailing blank line separates this
// hop from the next one.
void print_trace_packet_dig(const ldns_pkt *pkt, const CliOptions &opts, Millis query_time, const TraceServer &server) {
    // `+tcp` rewrites every trace hop to `tcp://` (see run_trace), so the
    // transport rendered in the stats footer is driven by opts.force_tcp.
    std::string text = format_trace_packet_dig(pkt, opts.display, query_time, server.ip, server.name, opts.force_tcp);
    std::fputs(text.c_str(), stdout);
    // Keep the per-hop display in sync with any stderr error that follows
    // (e.g. the "could not resolve any authoritative servers" final error, or
    // an "exchange failed" hop): without this flush the buffered stdout output
    // can land after the stderr error in a merged stream, mirroring the same
    // fflush discipline `print_packet_dig` already uses above. This is the
    // trace-mode fix for the spurious `Error: ... before the first hop's
    // output` mis-ordering: the trace's stdout is line-buffered when connected
    // to a terminal but fully buffered when piped, so stderr (unbuffered)
    // wins the race without an explicit flush here.
    std::fflush(stdout);
}

// Strip the trailing root-label dot (`a.root-servers.net.` -> `a.root-servers.net`).
// ldns returns NS target names fully-qualified; dig's `Received` footer prints
// the name without the trailing dot.
std::string strip_trailing_dot(std::string_view name) {
    if (!name.empty() && name.back() == '.') {
        return std::string(name.substr(0, name.size() - 1));
    }
    return std::string(name);
}

void print_packet_short(const ldns_pkt *pkt) {
    const ldns_rr_list *answers = ldns_pkt_answer(pkt);
    if (answers == nullptr) {
        return;
    }
    size_t count = ldns_rr_list_rr_count(answers);
    for (size_t i = 0; i < count; ++i) {
        const ldns_rr *rr = ldns_rr_list_rr(answers, i);
        size_t rdf_count = ldns_rr_rd_count(rr);
        for (size_t j = 0; j < rdf_count; ++j) {
            AllocatedPtr<char> rdf_str(ldns_rdf2str(ldns_rr_rdf(rr, j)));
            if (rdf_str != nullptr) {
                if (j != 0) {
                    std::fputc(' ', stdout);
                }
                std::fputs(rdf_str.get(), stdout);
            }
        }
        std::fputc('\n', stdout);
    }
}

Task<QueryOutcome> run_query(EventLoop &loop, const CliOptions &opts) {
    co_await loop.co_submit();
    auto verifier = make_verifier();
    SocketFactory socket_factory({
            .loop = loop,
            .verifier = std::move(verifier),
    });
    UpstreamFactory factory({
            .loop = loop,
            .socket_factory = &socket_factory,
            .ipv6_available = !opts.ipv4_only,
            .enable_http3 = false,
            .timeout = opts.timeout,
    });
    UpstreamOptions upstream_opts{.address = opts.server, .bootstrap = effective_bootstrap(opts.bootstrap)};
    auto upstream_res = factory.create_upstream(upstream_opts);
    if (upstream_res.has_error()) {
        co_return QueryOutcome{.error = fmt::format("upstream create failed: {}", upstream_res.error()->str())};
    }
    UpstreamPtr &upstream = upstream_res.value();
    ldns_pkt_ptr query = make_query(opts.name, opts.rr_type, opts.recurse);
    if (query == nullptr) {
        co_return QueryOutcome{.error = fmt::format("invalid domain name: {}", opts.name)};
    }
    apply_dns_flags(query.get(), opts);
    if (opts.print_query) {
        // +qr: echo the query packet before sending, mirroring `dig +qr`.
        print_packet_dig(query.get(), opts, true, Millis{0});
    }
    auto start = std::chrono::steady_clock::now();
    auto reply = co_await upstream->exchange(query.get());
    auto end = std::chrono::steady_clock::now();
    upstream.reset();
    if (reply.has_error()) {
        co_return QueryOutcome{.error = fmt::format("exchange failed: {}", reply.error()->str())};
    }
    Millis query_time = std::chrono::duration_cast<Millis>(end - start);
    co_return QueryOutcome{.reply = std::move(reply.value()), .query_time = query_time};
}

std::vector<std::string> extract_ns_names(const ldns_pkt *pkt) {
    // dig +trace extracts the NS target names that drive the next iteration.
    // For a typical referral they live in the AUTHORITY section; for the
    // initial `.` NS query the cached answer carries them in ANSWER. Look at
    // AUTHORITY first (the common case), then fall back to ANSWER so the
    // seeded trace hop's NS records are picked up either way.
    std::vector<std::string> names;
    auto from_section = [&](const ldns_rr_list *section) {
        if (section == nullptr) {
            return;
        }
        for (size_t i = 0; i < ldns_rr_list_rr_count(section); ++i) {
            const ldns_rr *rr = ldns_rr_list_rr(section, i);
            if (ldns_rr_get_type(rr) == LDNS_RR_TYPE_NS) {
                AllocatedPtr<char> ns_name(ldns_rdf2str(ldns_rr_rdf(rr, 0)));
                if (ns_name != nullptr) {
                    names.emplace_back(ns_name.get());
                }
            }
        }
    };
    from_section(ldns_pkt_authority(pkt));
    if (names.empty()) {
        from_section(ldns_pkt_answer(pkt));
    }
    return names;
}

// Resolves an NS hostname (for glueless referrals) using the first bootstrap
// server (or the system resolver when none was given). Returns the first A
// record found, or nullopt on failure.
Task<std::optional<std::string>> resolve_ns_via_bootstrap(
        EventLoop &loop, SocketFactory &socket_factory, const std::string &name, const CliOptions &opts) {
    co_await loop.co_submit();
    std::vector<std::string> bootstrap = effective_bootstrap(opts.bootstrap);
    if (bootstrap.empty()) {
        co_return std::nullopt;
    }
    UpstreamFactory factory({
            .loop = loop,
            .socket_factory = &socket_factory,
            .ipv6_available = !opts.ipv4_only,
            .enable_http3 = false,
            .timeout = opts.timeout,
    });
    UpstreamOptions upstream_opts{.address = bootstrap.front()};
    auto upstream_res = factory.create_upstream(upstream_opts);
    if (upstream_res.has_error()) {
        co_return std::nullopt;
    }
    UpstreamPtr &upstream = upstream_res.value();
    ldns_pkt_ptr query = make_query(name, LDNS_RR_TYPE_A, true);
    if (query == nullptr) {
        co_return std::nullopt;
    }
    auto reply = co_await upstream->exchange(query.get());
    upstream.reset();
    if (reply.has_error()) {
        co_return std::nullopt;
    }
    const ldns_rr_list *answers = ldns_pkt_answer(reply.value().get());
    if (answers == nullptr) {
        co_return std::nullopt;
    }
    for (size_t i = 0; i < ldns_rr_list_rr_count(answers); ++i) {
        const ldns_rr *rr = ldns_rr_list_rr(answers, i);
        if (ldns_rr_get_type(rr) == LDNS_RR_TYPE_A) {
            AllocatedPtr<char> addr(ldns_rdf2str(ldns_rr_rdf(rr, 0)));
            if (addr != nullptr) {
                co_return std::optional<std::string>(addr.get());
            }
        }
    }
    co_return std::nullopt;
}

// Result of a single trace-mode exchange: the reply packet plus the elapsed
// wall-clock time. `error` is empty on success and carries the upstream error
// string on failure.
struct TraceExchangeResult {
    ldns_pkt_ptr reply;
    Millis elapsed{};
    std::string error;
};

// Performs one DNS exchange over an existing socket factory: builds an
// upstream to `address`, constructs a query for `name`/`rr_type`, applies the
// EDNS-layer CLI flags, and sends it. Measures the round-trip time so the trace
// footer (`... in Y ms`) reflects real per-hop latency, mirroring `dig`.
Task<TraceExchangeResult> trace_exchange(EventLoop &loop, SocketFactory &socket_factory, const CliOptions &opts,
        const std::string &address, const std::string &name, ldns_rr_type rr_type, bool recurse) {
    co_await loop.co_submit();
    UpstreamFactory factory({
            .loop = loop,
            .socket_factory = &socket_factory,
            .ipv6_available = !opts.ipv4_only,
            .enable_http3 = false,
            .timeout = opts.timeout,
    });
    UpstreamOptions upstream_opts{.address = address};
    auto upstream_res = factory.create_upstream(upstream_opts);
    if (upstream_res.has_error()) {
        co_return TraceExchangeResult{
                .error = fmt::format("upstream create failed for {}: {}", address, upstream_res.error()->str())};
    }
    UpstreamPtr &upstream = upstream_res.value();
    ldns_pkt_ptr query = make_query(name, rr_type, recurse);
    if (query == nullptr) {
        co_return TraceExchangeResult{.error = fmt::format("invalid domain name: {}", name)};
    }
    apply_dns_flags(query.get(), opts);
    auto start = std::chrono::steady_clock::now();
    auto reply = co_await upstream->exchange(query.get());
    auto end = std::chrono::steady_clock::now();
    upstream.reset();
    if (reply.has_error()) {
        co_return TraceExchangeResult{
                .error = fmt::format("exchange failed for {}: {}", address, reply.error()->str())};
    }
    Millis elapsed = std::chrono::duration_cast<Millis>(end - start);
    co_return TraceExchangeResult{.reply = std::move(reply.value()), .elapsed = elapsed};
}

// Extracts the next hop's authoritative servers from a referral / cached
// response: NS target names from ANSWER or AUTHORITY paired with their A/AAAA
// glue addresses from ADDITIONAL (A preferred over AAAA; IPv6 glue skipped under
// -4 via glue_address_usable). Glueless NS hostnames — and NS hostnames whose
// only glue is IPv6 under -4 — are resolved via the bootstrap resolver (which
// queries A only, so an IPv6-only NS yields no address under -4). Returns at
// least one entry on success.
Task<std::vector<TraceServer>> next_trace_servers(
        EventLoop &loop, SocketFactory &socket_factory, const ldns_pkt *response, const CliOptions &opts) {
    co_await loop.co_submit();
    std::vector<TraceServer> next;
    if (response == nullptr) {
        co_return next;
    }
    std::vector<std::string> ns_names = extract_ns_names(response);
    std::map<std::string, GlueAddress> glue = additional_glue(response);
    for (const std::string &ns : ns_names) {
        std::string display_name = strip_trailing_dot(ns);
        if (auto it = glue.find(ns); it != glue.end() && glue_address_usable(it->second, opts.ipv4_only)) {
            next.push_back({it->second.address, display_name});
            continue;
        }
        // Glueless referral, or IPv6 glue suppressed by -4: resolve the NS
        // hostname's A record via the bootstrap resolver so the trace can
        // continue. resolve_ns_via_bootstrap only queries A (IPv4), so under -4
        // an IPv6-only NS yields no address and is dropped.
        auto resolved = co_await resolve_ns_via_bootstrap(loop, socket_factory, ns, opts);
        if (resolved.has_value()) {
            next.push_back({*resolved, display_name});
        }
    }
    co_return next;
}

Task<TraceOutcome> run_trace(EventLoop &loop, const CliOptions &opts) {
    co_await loop.co_submit();
    auto verifier = make_verifier();
    SocketFactory socket_factory({
            .loop = loop,
            .verifier = std::move(verifier),
    });

    // Seeded first hop: query the user's @server for "." NS (RD=1) to obtain
    // the root name-server delegation, mirroring `dig +trace` (which always
    // starts with a recursive `.` NS query to the configured resolver). The
    // response carries the root NS records plus their glue, which feed the
    // iteration loop below. If @server is unreachable (or yields no servers),
    // fall back to the checked-in IANA root hints; see root_servers.h.
    std::vector<TraceServer> servers;
    {
        TraceServer server;
        // `server.name` is left empty so the footer falls back to the bare host
        // extracted from `opts.server` (via `split_trace_server_addr`) rather
        // than echoing the raw `@server` value into the `(NAME)` parens —
        // which would leak a stale `:port` / scheme prefix (e.g. `1.1.1.1:5353`
        // or `tcp://1.1.1.1`) into the dig-style `IP#<port>(NAME)` footer.
        server.ip = opts.server;
        std::string initial_address = opts.server;
        if (opts.force_tcp) {
            apply_force_tcp(initial_address);
        }
        auto exchange =
                co_await trace_exchange(loop, socket_factory, opts, initial_address, ".", LDNS_RR_TYPE_NS, true);
        if (exchange.error.empty() && exchange.reply != nullptr) {
            ldns_pkt *response = exchange.reply.get();
            print_trace_packet_dig(response, opts, exchange.elapsed, server);
            servers = co_await next_trace_servers(loop, socket_factory, response, opts);
        }
    }
    // Fall back to the built-in root hints if the seeded hop did not produce a
    // usable server list (e.g. @server was unreachable or returned no NS).
    if (servers.empty()) {
        for (const root_hints::RootServer &root : root_hints::ROOT_SERVERS) {
            servers.push_back({std::string(root.ip), fmt::format("{}.root-servers.net", root.id)});
        }
    }

    // Iterative resolution: walk the delegation chain from the root, sending
    // RD=0 queries for `opts.name` / `opts.rr_type` to each hop's authoritative
    // server. Terminate when an authoritative answer (AA bit) is set, or when
    // the response carries answers (ancount > 0).
    for (size_t iteration = 0; iteration < MAX_TRACE_ITERATIONS; ++iteration) {
        if (servers.empty()) {
            co_return TraceOutcome{.error = "no servers available to continue tracing"};
        }
        TraceServer server = servers.front();
        std::string address = opts.force_tcp ? fmt::format("tcp://{}", server.ip) : server.ip;
        auto exchange = co_await trace_exchange(loop, socket_factory, opts, address, opts.name, opts.rr_type, false);
        if (!exchange.error.empty()) {
            co_return TraceOutcome{
                    .error = fmt::format("{}: {}", server.name.empty() ? server.ip : server.name, exchange.error)};
        }
        ldns_pkt *response = exchange.reply.get();
        print_trace_packet_dig(response, opts, exchange.elapsed, server);
        if (ldns_pkt_ancount(response) > 0 || ldns_pkt_aa(response)) {
            co_return TraceOutcome{};
        }
        auto next_servers = co_await next_trace_servers(loop, socket_factory, response, opts);
        if (next_servers.empty()) {
            co_return TraceOutcome{.error = "could not resolve any authoritative servers"};
        }
        servers = std::move(next_servers);
    }
    co_return TraceOutcome{.error = "maximum trace iterations reached"};
}

} // namespace

int main(int argc, char *argv[]) {
    // Seed ldns's PRNG so query transaction IDs are unpredictable.
    // ldns_get_random() (called via ldns_pkt_set_random_id in make_query) uses
    // POSIX random() when HAVE_SSL is undefined (the case in this ldns build).
    // Without ldns_init_random(), random() defaults to seed 1 and the first
    // ldns_get_random() truncation to 16 bits always yields 0x4567 = 17767,
    // making every transaction ID identical across runs — a classic cache-
    // poisoning / spoofing vulnerability (CVE-2008-1447 / Kaminsky attack).
    // ldns_init_random() reads from /dev/urandom and calls srandom(), which is
    // exactly the initialization ldns documents as mandatory when OpenSSL is
    // unavailable (see the comment on ldns_init_random in ldns/util.c).
    (void) ldns_init_random(nullptr, 0);

    ag::adyg::ParseResult parsed = ag::adyg::parse_args(argc, argv);
    if (parsed.help_requested) {
        return print_usage(argv[0]);
    }
    if (parsed.version_requested) {
        fmt::print("adyg {}\n", AG_DNSLIBS_VERSION);
        return 0;
    }
    if (!parsed.error.empty()) {
        fmt::print(stderr, "Error: {}\n", parsed.error);
        return 1;
    }
    auto &opts = parsed.opts;

    if (opts.name.empty()) {
        fmt::print(stderr, "Error: no domain name specified\n\n");
        print_usage(argv[0]);
        return 1;
    }

    // When no @server was given, query the system's configured DNS server
    // (mirrors `dig`), reusing the upstream module's system resolver
    // (system://) where available and falling back to DEFAULT_SERVER elsewhere.
    // This is applied unconditionally — including for +trace: run_trace() seeds
    // its first hop (a recursive `.` NS query) from opts.server, mirroring
    // `dig +trace` which always starts by querying the configured resolver and
    // only falls back to the checked-in root hints if that hop yields no
    // servers.
    if (opts.server.empty()) {
        opts.server = default_server();
    }

    // `-p PORT` overrides the plain-DNS port (applied before +tcp's scheme
    // rewrite so the port survives: `1.1.1.1:5353` -> `tcp://1.1.1.1:5353`).
    // +trace dials literal per-hop IPs directly, so -p is a no-op there.
    if (opts.port.has_value() && !opts.trace) {
        apply_port(opts.server, opts.port);
    }
    if (opts.force_tcp && !opts.trace) {
        apply_force_tcp(opts.server);
    }

    // +cmd: echo the command line (mirrors `dig`'s banner). `dig` starts with a
    // leading blank line, then `; <<>> DiG ... <<>>`, then `; (1 server found)`
    // (adyg always queries exactly one server), then `;; global options: +cmd`.
    // `+short` suppresses the whole banner unconditionally (even with `+cmd`),
    // matching `dig`'s RDATA-only short output. Stdout is flushed so a later
    // stderr error lands after the banner in a merged stream, mirroring `dig`.
    if (cmd_banner_enabled(opts)) {
        std::string cmd = fmt::format("; <<>> adyg {} <<>>", AG_DNSLIBS_VERSION);
        for (int i = 1; i < argc; ++i) {
            cmd += ' ';
            cmd += argv[i];
        }
        fmt::print("\n{}\n; (1 server found)\n;; global options: +cmd\n", cmd);
        std::fflush(stdout);
    }

    EventLoopPtr loop = EventLoop::create();
    if (loop == nullptr) {
        fmt::print(stderr, "Error: failed to create event loop\n");
        return 1;
    }
    loop->start();
    int exit_code = 0;
    if (opts.trace) {
        auto outcome = to_future(run_trace(*loop, opts)).get();
        if (!outcome.error.empty()) {
            fmt::print(stderr, "Error: {}\n", outcome.error);
            exit_code = 1;
        }
    } else {
        auto outcome = to_future(run_query(*loop, opts)).get();
        if (!outcome.error.empty()) {
            fmt::print(stderr, "Error: {}\n", outcome.error);
            exit_code = 1;
        } else if (outcome.reply != nullptr) {
            if (opts.short_output) {
                print_packet_short(outcome.reply.get());
            } else {
                print_packet_dig(outcome.reply.get(), opts, false, outcome.query_time);
            }
        }
    }
    loop->stop();
    loop->join();
    return exit_code;
}
