#include <atomic>
#include <csignal>
#include <cstring>
#include <functional>
#include <future>
#include <memory>
#include <span>
#include <thread>

#include <fmt/chrono.h>
#include <ldns/ldns.h>

#include "common/gtest_coro.h"
#include "common/logger.h"
#include "common/parallel.h"
#include "common/utils.h"
#include "dns/dnscrypt/dns_crypt_ldns.h"
#include "dns/upstream/upstream.h"
#include "dns/upstream/upstream_utils.h"
#ifdef __ANDROID__
#include "android_res_api.h"
#endif

#include "dns/dnsstamp/dns_stamp.h"
#include "dns_test_helpers.h"
#include "integration_test_guard.h"
#include "loopback_dns_server.h"
#include "loopback_dnscrypt_server.h"
#include "loopback_doh_server.h"
#include "loopback_quic_server.h"
#include "loopback_tls_server.h"
#include "test_certificates.h"

namespace ag::dns::upstream::test {

static constexpr Secs DEFAULT_TIMEOUT(10);
// Only used on the integration path (real servers, rate-limited). The offline
// path (loopback) needs no delay between requests.
static constexpr Millis DELAY_BETWEEN_REQUESTS{500};

using TestError = std::optional<std::string>;

static struct Init {
    Init() {
#ifdef SIGPIPE
        std::signal(SIGPIPE, SIG_IGN);
#endif
    }
} init_;

static Logger logger{"test_upstream"};

namespace concat_err_string {

TestError &operator+=(TestError &result, const TestError &err) {
    if (err) {
        if (!result) {
            result = std::string{};
        }
        if (result) {
            *result += AG_FMT("{}\n", *err);
        }
    }
    return result;
}

} // namespace concat_err_string

static ldns_pkt_ptr create_test_message() {
    ldns_pkt *pkt = ldns_pkt_query_new(
            ldns_dname_new_frm_str("google-public-dns-a.google.com."), LDNS_RR_TYPE_A, LDNS_RR_CLASS_IN, LDNS_RD);
    static size_t id = 0;
    ldns_pkt_set_id(pkt, id++);
    return ldns_pkt_ptr(pkt);
}

[[nodiscard]] static TestError assert_response(const ldns_pkt &reply) {
    size_t ancount = ldns_pkt_ancount(&reply);
    if (ancount != 1) {
        return AG_FMT("DNS upstream returned reply with wrong number of answers: {}", ancount);
    }
    ldns_rr *first_rr = ldns_rr_list_rr(ldns_pkt_answer(&reply), 0);
    if (ldns_rr_get_type(first_rr) != LDNS_RR_TYPE_A) {
        return AG_FMT("DNS upstream returned wrong answer type instead of A: {}",
                ldns_rr_type2str(ldns_rr_get_type(first_rr)));
    }
    ldns_rdf *rdf = ldns_rr_rdf(first_rr, 0);
    static constexpr std::array<uint8_t, 4> ip8888 = {8, 8, 8, 8};
    if (ldns_rdf_size(rdf) != ip8888.size() || 0 != std::memcmp(ldns_rdf_data(rdf), ip8888.data(), ip8888.size())) {
        return "DNS upstream returned wrong answer instead of 8.8.8.8";
    }
    return std::nullopt;
}

[[nodiscard]] static coro::Task<TestError> check_upstream(Upstream &upstream, const std::string &addr) {
    auto req = create_test_message();
    auto reply = co_await upstream.exchange(req.get());
    if (reply.has_error()) {
        co_return AG_FMT("Couldn't talk to upstream {}: {}", addr, reply.error()->str());
    }
    co_return assert_response(*reply.value());
}

static coro::Task<void> check_all_results(const std::vector<TestError> &errors) {
    using namespace concat_err_string;
    TestError err;
    for (auto &error : errors) {
        err += error;
    }
    ASSERT_FALSE(err) << *err;
}

template <typename F>
static auto parallel_run_n(EventLoop &loop, size_t count, const F &f) {
    auto all_of_awaitable = parallel::all_of<TestError>();
    for (size_t i = 0; i != count; i++) {
        all_of_awaitable.add(f(i));
    }
    return all_of_awaitable;
}

template <typename F>
static coro::Task<void> parallel_test_basic_n(EventLoop &loop, size_t count, const F &f) {
    co_await loop.co_submit();
    auto results = co_await parallel_run_n(loop, count, f);
    co_await check_all_results(results);
}

struct UpstreamTestData {
    std::string address;
    std::vector<std::string> bootstrap;
    IpAddress server_ip;
};

// Builds a canned A reply echoing the request's qname with rdata `ip`, so
// that loopback responders can drive assert_response() (which expects exactly
// one A answer == 8.8.8.8) without internet access. `ip` defaults to 8.8.8.8
// for exchange queries; bootstrap resolvers pass "127.0.0.1" so a hostname
// upstream resolves to the loopback TLS server.
static ldns_pkt_ptr make_loopback_a_reply(const ldns_pkt &req, std::string_view ip = "8.8.8.8") {
    ldns_pkt_ptr reply = ag::test::make_base_reply(req);
    const ldns_rr *question = ldns_rr_list_rr(ldns_pkt_question(&req), 0);
    if (question == nullptr) {
        return {};
    }
    ldns_rr *answer = ldns_rr_new();
    ldns_rr_set_owner(answer, ldns_rdf_clone(ldns_rr_owner(question)));
    ldns_rr_set_ttl(answer, 300);
    ldns_rr_set_type(answer, LDNS_RR_TYPE_A);
    ldns_rr_set_class(answer, LDNS_RR_CLASS_IN);
    ldns_rr_push_rdf(answer, ldns_rdf_new_frm_str(LDNS_RDF_TYPE_A, std::string{ip}.c_str()));
    ldns_pkt_push_rr(reply.get(), LDNS_SECTION_ANSWER, answer);
    return reply;
}

class UpstreamTest : public ::testing::Test {
protected:
    EventLoopPtr m_loop;
    std::unique_ptr<SocketFactory> m_socket_factory;
    // In-process loopback DNS responder (127.0.0.1). Replies with a canned
    // 8.8.8.8 A answer, so the offline tests never reach the public internet.
    ag::test::LoopbackDnsServer m_loopback{[](const ldns_pkt &req) {
        return make_loopback_a_reply(req);
    }};
    // In-process loopback DoT responder (127.0.0.1). Replies with the same
    // canned 8.8.8.8 A answer as m_loopback, over TLS. The self-signed cert is
    // accepted on the client side by TestCertificateVerifier{ACCEPT_ALL} (set
    // in make_upstream_factory()), so DoT tests run fully offline.
    ag::test::LoopbackTlsServer m_loopback_tls{[](const ldns_pkt &req) {
        return make_loopback_a_reply(req);
    }};
    // In-process loopback DoH responder (127.0.0.1, HTTP/2 over TLS). Replies
    // with the same canned 8.8.8.8 A answer. The cert is accepted via
    // TestCertificateVerifier{ACCEPT_ALL}; the DohUpstream client always
    // offers ["h2","http/1.1"] ALPN and the server prefers h2, so the
    // HTTP/2 path is exercised by default.
    ag::test::LoopbackDohServer m_loopback_doh{[](const ldns_pkt &req) {
        return make_loopback_a_reply(req);
    }};
    // In-process loopback DoQ responder (127.0.0.1, ALPN "doq", RFC 9250
    // 2-byte stream framing). Replies with the same canned 8.8.8.8 A answer
    // over raw QUIC. The cert is accepted via TestCertificateVerifier{ACCEPT_ALL}.
    ag::test::LoopbackQuicServer m_loopback_doq{[](const ldns_pkt &req) {
        return make_loopback_a_reply(req);
    }};
    // In-process loopback DoH3 responder (127.0.0.1, ALPN "h3", HTTP/3 over
    // QUIC via Http3Server::accept()). Replies with the same canned 8.8.8.8 A
    // answer, handling GET ?dns= the same way as the DoH server. Replaces the
    // former real h3://cloudflare-dns.com entry so the default suite is offline.
    ag::test::LoopbackQuicServer m_loopback_doh3{
            [](const ldns_pkt &req) {
                return make_loopback_a_reply(req);
            },
            ag::test::LoopbackQuicServer::QuicMode::DOH3,
    };

    void SetUp() override {
#if 0
        // It is too verbose for a CI report, and also the output in the stderr on Windows
        // is too slow, so that tests with small timeouts may fail
        Logger::set_log_level(LOG_LEVEL_TRACE);
#endif
        m_loop = EventLoop::create();
        m_loop->start();
        make_upstream_factory();
        m_loopback.start();
        m_loopback_tls.start();
        m_loopback_doh.start();
        m_loopback_doq.start();
        m_loopback_doh3.start();
    }

    void TearDown() override {
        m_loopback_doh3.stop();
        m_loopback_doq.stop();
        m_loopback_doh.stop();
        m_loopback_tls.stop();
        m_loopback.stop();
        m_loop->stop();
        m_loop->join();
    }

    void make_upstream_factory(OutboundProxySettings *oproxy = nullptr) {
        struct SocketFactory::Parameters sf_parameters = {.loop = *m_loop};
        // Use the in-process TestCertificateVerifier so the loopback DoT
        // server's self-signed cert (from test_certificates.h) is accepted.
        // Plain DNS tests are unaffected (they never reach TLS verification).
        sf_parameters.verifier = std::make_unique<ag::test::TestCertificateVerifier>(
                ag::test::TestCertificateVerifier::Mode::ACCEPT_ALL);

#if 0
        static OutboundProxySettings proxy_settings =
                { OutboundProxyProtocol::SOCKS5_UDP, "127.0.0.1", 8888, { { "1", "1" } } };
        sf_parameters.oproxy_settings = &proxy_settings;
#else
        sf_parameters.oproxy.settings = oproxy;
#endif

        m_socket_factory = std::make_unique<SocketFactory>(std::move(sf_parameters));
    }

    UpstreamFactory::CreateResult create_upstream(const UpstreamOptions &opts, Millis timeout = DEFAULT_TIMEOUT) {
        // `ipv6_available` matches the production default (true). The former
        // static-init probe dialed Google DNS over IPv6 on the first
        // create_upstream() call, which kept the suite online; for literal-IP
        // loopback upstreams the flag is inert (the bootstrapper is bypassed),
        // so a literal true is correct.
        UpstreamFactory factory({
                .loop = *m_loop,
                .socket_factory = m_socket_factory.get(),
                .ipv6_available = true,
                .enable_http3 = false,
                .timeout = timeout,
        });
        return factory.create_upstream(opts);
    }

    coro::Task<TestError> check_upstream_internal(UpstreamPtr upstream, std::string addr) {
        co_await m_loop->co_submit();
        TestError error = co_await check_upstream(*upstream, addr);
        upstream.reset();
        co_return error;
    }

    // Iterates `test_data` sequentially, creating an upstream and exchanging
    // one query per entry. `delay_between` is only honored on the integration
    // path (real servers are rate-limited); the offline loopback path passes 0.
    coro::Task<void> sequential_test(std::span<const UpstreamTestData> test_data, Millis delay_between = Millis{0}) {
        for (const UpstreamTestData &data : test_data) {
            infolog(logger, "Testing upstream: {}", data.address);
            if (delay_between.count() > 0) {
                std::this_thread::sleep_for(delay_between);
            }
            auto upstream_res = create_upstream({data.address, data.bootstrap, data.server_ip});

#ifdef __ANDROID__
            // Skip system:// tests if Android API is not available
            if (data.address.starts_with("system://")) {
                if (!AndroidResApi::is_available()) {
                    infolog(logger, "Skipping system:// test - Android API not available");
                    continue;
                }
            }
#endif

            ASSERT_FALSE(upstream_res.has_error()) << AG_FMT(
                    "Failed to generate upstream from address {}: {}", data.address, upstream_res.error()->str());
            auto error = coro::to_future(check_upstream_internal(std::move(upstream_res.value()), data.address)).get();
            ASSERT_FALSE(error) << *error;
        }
    }

    // "<scheme>://127.0.0.1:<port>" for the loopback server.
    std::string local_udp() const {
        return m_loopback.address(ag::utils::TP_UDP);
    }
    std::string local_tcp() const {
        return m_loopback.address(ag::utils::TP_TCP);
    }
    // Plain (no-scheme) loopback address: makes PlainUpstream try UDP first
    // and fall back to TCP on a truncated reply.
    std::string local_plain() const {
        return AG_FMT("127.0.0.1:{}", m_loopback.port());
    }
    // "tls://127.0.0.1:<port>" for the loopback DoT server. A literal IP, so
    // the bootstrapper is bypassed and DotUpstream connects directly.
    std::string local_dot() const {
        return m_loopback_tls.address();
    }
    // "https://127.0.0.1:<port>/dns-query" for the loopback DoH server. A
    // literal IP, so the bootstrapper is bypassed and DohUpstream connects
    // directly.
    std::string local_doh() const {
        return m_loopback_doh.address();
    }
    // DoH stamp (sdns://) encoding 127.0.0.1:<port> + /dns-query, so the
    // stamp-parsing code path in the upstream factory is exercised. props
    // is set (to empty) so str() emits an sdns:// stamp rather than falling
    // back to pretty_url().
    std::string local_doh_stamp() const {
        ServerStamp stamp{};
        stamp.proto = StampProtoType::DOH;
        stamp.server_addr_str = AG_FMT("127.0.0.1:{}", m_loopback_doh.port());
        stamp.provider_name = "127.0.0.1";
        stamp.path = "/dns-query";
        stamp.props = ServerInformalProperties{};
        return stamp.str();
    }
    // Credentialed DoH URL: https://username:password@127.0.0.1:<port>/dns-query
    std::string local_doh_url_with_creds() const {
        std::string addr = m_loopback_doh.address();          // https://127.0.0.1:<port>/dns-query
        return "https://username:password@" + addr.substr(8); // 8 = strlen("https://")
    }
    // Credentialed DoH stamp: sdns://username:password@<base64_payload>
    std::string local_doh_stamp_with_creds() const {
        std::string sdns = local_doh_stamp();                // sdns://<base64>
        return "sdns://username:password@" + sdns.substr(7); // 7 = strlen("sdns://")
    }
    // "quic://127.0.0.1:<port>" for the loopback DoQ server. A literal IP, so
    // the bootstrapper is bypassed and DoqUpstream connects directly.
    std::string local_doq() const {
        return m_loopback_doq.address();
    }
    // "h3://127.0.0.1:<port>/dns-query" for the loopback DoH3 server. A literal
    // IP, so the bootstrapper is bypassed and DohUpstream connects directly
    // over HTTP/3.
    std::string local_doh3() const {
        return m_loopback_doh3.address();
    }
    // DoQ stamp (sdns://) encoding the port with a literal-IP provider_name,
    // so the stamp-parsing code path in the upstream factory is exercised. The
    // server_addr_str is port-only (":<port>") so resolved_server_ip is NOT
    // set (which would force DEFAULT_DOQ_PORT); instead the bootstrapper
    // short-circuits on the literal IP and uses the correct port. Replaces the
    // former real AdGuard DoQ stamp.
    std::string local_doq_stamp() const {
        ServerStamp stamp{};
        stamp.proto = StampProtoType::DOQ;
        stamp.server_addr_str = AG_FMT(":{}", m_loopback_doq.port());
        stamp.provider_name = "127.0.0.1";
        stamp.props = ServerInformalProperties{};
        return stamp.str();
    }
};

template <typename... Ts>
struct UpstreamParamTest : public UpstreamTest, public ::testing::WithParamInterface<Ts...> {};

TEST_F(UpstreamTest, CreateUpstreamWithWrongOptions) {
    co_await m_loop->co_submit();
    static const UpstreamOptions OPTIONS[] = {
            // malformed ip address
            {"8..8.8:53"},
            {"8.a.8.8:53"},
            {"127.0.0.1:-1"},
            {"[::1::]"},
            {"tcp://8..8.8:53"},
            {"tcp://127.0.0.1,1.2.3.4"},
            {"127.0.0.1,1.2.3.4"},
#ifdef __APPLE__
            {"system://enqwerty"},
#endif // __APPLE__
#ifdef __ANDROID__
            {"system://invalidnetwork"},
#endif // __ANDROID__
       // no bootstrapper and resolved server address
            {"https://example.com"},
            {"tls://one.one.one.one"},

            // non-plain DNS bootstrapper has no explicit or malformed ip address
            {"https://example.com", {"https://example.com"}},
            {"https://example.com", {"1..1.1"}},
            {"tls://one.one.one.one", {"https://example.com"}},
            {"tls://one.one.one.one", {"1..1.1"}},

            // some degenerate URLs
            {"tls://", {"127.0.0.1"}},
            {"tls:///", {"127.0.0.1"}},
            {"tls://   ", {"127.0.0.1"}},
            {"tls://   /", {"127.0.0.1"}},
            {"tcp://", {}},
            {"tcp:///", {}},
            {"tcp://   ", {}},
            {"tcp://   /", {}},
            {"quic://", {}},
            {"quic://   ", {}},
            {"quic:///", {}},
            {"quic://   /", {}},
            {"https://", {}},
            {"https://   ", {}},
            {"https:///", {}},
            {"https://   /", {}},

            // wrong basic authentication parameters
            {"https://usernamepassword@127.0.0.1/dns-query", {"127.0.0.1"}},
            {"https://:pass@127.0.0.1/dns-query", {"127.0.0.1"}},
            {"sdns://usernamepassword@AgcAAAAAAAAABzEuMC4wLjEAEmRucy5jbG91ZGZsYXJlLmNvbQovZG5zLXF1ZXJ5", {}},
            {"sdns://:pass@AgcAAAAAAAAABzEuMC4wLjEAEmRucy5jbG91ZGZsYXJlLmNvbQovZG5zLXF1ZXJ5", {}},
    };

    for (const UpstreamOptions &options : OPTIONS) {
        UpstreamFactory::CreateResult r = create_upstream(options);
        ASSERT_TRUE(r.has_error()) << "Address should be bad: " << options.address << ", failing test";
    }
}

// DoH combos that must fail at exchange time, reproduced with dead loopback
// targets so the suite stays offline. Each row constructs successfully (init
// succeeds) but the exchange errors out, preserving the "must fail" semantics
// of the former real-DoH rows:
//  - dead port (literal IP, nothing listening on 127.0.0.1:1)
//  - dead bootstrap (hostname with a dead loopback bootstrap that can't resolve)
TEST_F(UpstreamTest, UseUpstreamWithWrongDohOptions) {
    co_await m_loop->co_submit();
    static const UpstreamOptions OPTIONS[]{
            {"https://127.0.0.1:1/dns-query", {}},
            {"https://localhost/dns-query", {"127.0.0.1:1"}},
    };

    for (const UpstreamOptions &options : OPTIONS) {
        auto upstream_res = create_upstream(options);
        ASSERT_FALSE(upstream_res.has_error()) << upstream_res.error()->str();

        ldns_pkt_ptr msg = create_test_message();
        auto reply_res = co_await upstream_res.value()->exchange(msg.get());
        ASSERT_TRUE(reply_res.has_error()) << "Expected this upstream to error out: " << options.address;
    }
}

// DoT combos that must fail at exchange time, reproduced with dead loopback
// targets so the suite stays offline. Each row constructs successfully (init
// succeeds) but the exchange errors out, preserving the "must fail" semantics
// of the former real-DoT rows:
//  - dead port (literal IP, nothing listening on 127.0.0.1:1)
//  - dead bootstrap (hostname with an unresolvable dead loopback bootstrap)
TEST_F(UpstreamTest, UseUpstreamWithWrongDotOptions) {
    co_await m_loop->co_submit();
    static const UpstreamOptions OPTIONS[]{
            {"tls://127.0.0.1:1", {}},
            {"tls://localhost", {"127.0.0.1:1"}},
    };

    for (const UpstreamOptions &options : OPTIONS) {
        auto upstream_res = create_upstream(options);
        ASSERT_FALSE(upstream_res.has_error()) << upstream_res.error()->str();

        ldns_pkt_ptr msg = create_test_message();
        auto reply_res = co_await upstream_res.value()->exchange(msg.get());
        ASSERT_TRUE(reply_res.has_error()) << "Expected this upstream to error out: " << options.address;
    }
}

// Real-domain combos that must fail at exchange time. These rely on real DNS
// resolution / real TLS servers (non-existent domain, existent domain with a
// wrong path, DoT with an invalid hostname / invalid bootstrap / wrong port),
// which the offline dead-loopback tests above can't reproduce, so they are
// gated. Kept in addition to the offline UseUpstreamWithWrong{Doh,Dot}Options
// tests so the integration suite still validates the real-server failure modes.
TEST_F(UpstreamTest, UseUpstreamWithWrongOptions) {
    REQUIRE_INTEGRATION();
    co_await m_loop->co_submit();
    static const UpstreamOptions OPTIONS[]{
            // non existent domain, valid bootstrap
            {"https://qwer.zxcv.asdf.", {"8.8.8.8"}},
            // existent domain, invalid bootstrap
            {"https://dns.adguard-dns.com/dnsquery", {"10.255.255.1"}},
            // DoT
            {"tls://one.one.two.asdf.", {"8.8.8.8"}},    // invalid/valid
            {"tls://one.one.one.one", {"10.255.255.1"}}, // valid/invalid
            {"tls://one.one.one.one:1234", {"8.8.8.8"}}, // invalid/valid
    };
    // The "invalid bootstrap" rows use an RFC 1918 private address
    // (10.255.255.1:53) rather than a public IP: nothing listens there (so
    // resolution genuinely fails), and a local filtering VPN does not intercept
    // traffic to private subnets the way it does for public resolvers (e.g.
    // 4.3.2.1, which is a live public resolver and would resolve the hostname,
    // making the "must fail" assertion flaky). A public "dead" IP would instead
    // be either intercepted/rerouted by such a VPN or reachable on some
    // networks, hence the private-subnet choice.

    for (const UpstreamOptions &options : OPTIONS) {
        auto upstream_res = create_upstream(options);
        ASSERT_FALSE(upstream_res.has_error()) << upstream_res.error()->str();

        ldns_pkt_ptr msg = create_test_message();
        auto reply_res = co_await upstream_res.value()->exchange(msg.get());
        ASSERT_TRUE(reply_res.has_error()) << "Expected this upstream to error out: " << options.address;
    }
}

// Tests DoT bootstrap timeout against a loopback target. The upstream is a
// hostname (localhost:<tls port>) bootstrapped via a loopback DNS server that
// accepts the query but never replies (handler returns nullptr), so the
// bootstrapper genuinely waits for the configured timeout — no sleep(), no
// public internet.
TEST_F(UpstreamTest, TestBootstrapTimeout) {
    using namespace std::chrono_literals;
    using namespace concat_err_string;
    static constexpr auto timeout = 100ms;
    static constexpr size_t count = 10;
    co_await m_loop->co_submit();
    // Non-responding loopback DNS bootstrap: accepts the connection/packet but
    // never sends a reply, forcing the resolver to time out for real.
    ag::test::LoopbackDnsServer dead_bootstrap{[](const ldns_pkt &) -> ldns_pkt_ptr {
        return nullptr;
    }};
    dead_bootstrap.start();
    // Bare IP:port (no scheme) so the resolver accepts it as a plain DNS bootstrap;
    // the server never replies, so resolution genuinely times out.
    auto dead_bootstrap_addr = AG_FMT("127.0.0.1:{}", dead_bootstrap.port());
    auto errs = co_await parallel_run_n(*m_loop, count, [&](size_t index) -> coro::Task<TestError> {
        infolog(logger, "Start {}", index);
        // Hostname upstream so the bootstrapper is exercised; the dead bootstrap
        // never resolves it, so the exchange times out within the configured window.
        auto upstream_res =
                create_upstream({AG_FMT("tls://localhost:{}", m_loopback_tls.port()), {dead_bootstrap_addr}}, timeout);
        if (upstream_res.has_error()) {
            co_return AG_FMT("Failed to create upstream: {}", upstream_res.error()->str());
        }
        ag::utils::Timer timer;
        auto req = create_test_message();
        auto reply_res = co_await upstream_res.value()->exchange(req.get());
        if (!reply_res.has_error()) {
            co_return "The upstream must have timed out";
        }
        auto elapsed = timer.elapsed<Millis>();
        if (elapsed > 2 * timeout) {
            co_return AG_FMT("Exchange took more time than the configured timeout: {}", elapsed);
        }
        infolog(logger, "Finished {}", index);
        co_return std::nullopt;
    });
    dead_bootstrap.stop();
    TestError err;
    for (size_t i = 0; i != errs.size(); ++i) {
        auto result = errs[i];
        if (result) {
            err += result;
            errlog(logger, "Aborted: {}", *result);
        } else {
            infolog(logger, "Got result from {}", i);
        }
    }
    ASSERT_FALSE(err) << *err;
}

// Offline path for the truncated-reply behavior: a loopback server returns a
// truncated reply (TC=1) over UDP, forcing PlainUpstream to retry over TCP,
// where the server returns a non-truncated reply (TC=0). Exercises the real
// UDP->TCP fallback with no internet access.
TEST_F(UpstreamTest, DnsTruncatedLocal) {
    co_await m_loop->co_submit();
    auto tc_call = std::make_shared<std::atomic<int>>(0);
    ag::test::LoopbackDnsServer server([tc_call](const ldns_pkt &req) -> ldns_pkt_ptr {
        ldns_pkt_ptr reply = ag::test::make_base_reply(req);
        // First call (the UDP attempt) is truncated; the TCP retry is not.
        int n = tc_call->fetch_add(1);
        ldns_pkt_set_tc(reply.get(), n == 0);
        return reply;
    });
    server.start();
    auto upstream_res = create_upstream({AG_FMT("127.0.0.1:{}", server.port())}, Secs(5));
    ASSERT_FALSE(upstream_res.has_error()) << "Error while creating an upstream: " << upstream_res.error()->str();
    auto request = dnscrypt::create_request_ldns_pkt(
            LDNS_RR_TYPE_TXT, LDNS_RR_CLASS_IN, LDNS_RD, "unit-test-truncated.example.", std::nullopt);
    ldns_pkt_set_random_id(request.get());
    auto res = co_await upstream_res.value()->exchange(request.get());
    ASSERT_FALSE(res.has_error()) << "Error while making a request: " << res.error()->str();
    ASSERT_FALSE(ldns_pkt_tc(res->get())) << "Response must NOT be truncated";
    server.stop();
}

// Offline: the DNSCrypt truncation-handling path against a loopback DNSCrypt
// responder. The local server returns a truncated reply (TC=1) on the first
// (UDP) relay, forcing DnscryptUpstream to retry over TCP, where the server
// returns a non-truncated reply (TC=0). The final response is therefore not
// truncated — reproducing the former real-AdGuard assertion with no internet,
// and exercising the real UDP->TCP fallback over the encrypted relay.
TEST_F(UpstreamTest, DnsTruncatedDnscryptLocal) {
    co_await m_loop->co_submit();
    auto tc_call = std::make_shared<std::atomic<int>>(0);
    ag::test::LoopbackDnscryptServer server([tc_call](const ldns_pkt &req) -> ldns_pkt_ptr {
        ldns_pkt_ptr reply = ag::test::make_base_reply(req);
        // First relay (the UDP attempt) is truncated; the TCP retry is not.
        int n = tc_call->fetch_add(1);
        ldns_pkt_set_tc(reply.get(), n == 0);
        return reply;
    });
    server.start();
    auto upstream_res = create_upstream({server.stamp(), {}}, Secs(5));
    ASSERT_FALSE(upstream_res.has_error()) << "Error while creating an upstream: " << upstream_res.error()->str();
    auto request = dnscrypt::create_request_ldns_pkt(
            LDNS_RR_TYPE_TXT, LDNS_RR_CLASS_IN, LDNS_RD, "unit-test2.dns.adguard-dns.com.", std::nullopt);
    ldns_pkt_set_random_id(request.get());
    auto res = co_await upstream_res.value()->exchange(request.get());
    ASSERT_FALSE(res.has_error()) << "Error while making a request: " << res.error()->str();
    ASSERT_FALSE(ldns_pkt_tc(res->get())) << "Response must NOT be truncated";
    // The UDP reply was truncated, so a TCP retry must have happened.
    ASSERT_GE(tc_call->load(), 2);
    server.stop();
}

// Integration-only: real upstreams across all supported protocols (plain DNS,
// DoT, DoH, DoH3, DoQ, DNSCrypt). Testing against real servers validates the
// real handshake and resolution path, which a loopback server can't fully
// reproduce. Gated so the default suite stays offline; the offline loopback
// counterparts live in TestUpstreams{Local,DotLocal,DohLocal,DnscryptLocal,
// DoqDoh3Local} (always-on).
static const UpstreamTestData real_upstreams_data[]{
        {"udp://1.1.1.1:53", {}},
        {"tcp://8.8.8.8", {}},
#ifdef __APPLE__
        {"system://en0", {}},
#endif
#ifdef __ANDROID__
        {"system://", {}},
        {"system://eth0", {}},
#endif
        {"8.8.8.8:53", {"8.8.8.8:53"}},
        {"1.0.0.1", {}},
        {"1.1.1.1", {"1.0.0.1"}},
        {"tcp://1.1.1.1:53", {}},
        {"94.140.14.14:5353", {}},
        {"tls://1.1.1.1", {}},
        {"tls://9.9.9.9:853", {}},
        {"tls://dns.google", {"8.8.8.8:53"}},
        {"tls://dns.google:853", {"8.8.8.8:53"}},
        {"tls://dns.google:853", {"8.8.8.8"}},
        {"tls://one.one.one.one", {"1.0.0.1"}},
        {"https://dns9.quad9.net:443/dns-query", {"8.8.8.8"}},
        {"https://dns.cloudflare.com/dns-query", {"8.8.8.8:53"}},
        {"h3://cloudflare-dns.com/dns-query", {"8.8.8.8"}},
        {"https://dns.google/dns-query", {"8.8.8.8"}},
        {"https://username:password@dns.google/dns-query", {"8.8.8.8"}},
        {"sdns://username:password@AgcAAAAAAAAABzEuMC4wLjEAEmRucy5jbG91ZGZsYXJlLmNvbQovZG5zLXF1ZXJ5", {}},
        {// Cisco OpenDNS DNS (DNSCrypt) (no port in stamp, default port test)
                "sdns://"
                "AQEAAAAAAAAADjIwOC42Ny4yMjAuMTIzILc1EUAgbyJdPivYItf9aR6hwzzI1maNDL4Ev6vKQ_"
                "t5GzIuZG5zY3J5cHQtY2VydC5vcGVuZG5zLmNvbQ"},
        {// AdGuard DNS (DNSCrypt)
                "sdns://"
                "AQIAAAAAAAAAETk0LjE0MC4xNC4xNDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_"
                "OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20",
                {}},
        {// AdGuard Family (DNSCrypt)
                "sdns://"
                "AQIAAAAAAAAAETk0LjE0MC4xNC4xNTo1NDQzILgxXdexS27jIKRw3C7Wsao5jMnlhvhdRUXWuMm1AFq6ITIuZG5zY3J5cHQuZmFtaW"
                "x5Lm5zMS5hZGd1YXJkLmNvbQ",
                {"8.8.8.8"}},
        {// Cloudflare DNS (DoH)
                "sdns://AgcAAAAAAAAABzEuMC4wLjEAEmRucy5jbG91ZGZsYXJlLmNvbQovZG5zLXF1ZXJ5", {"8.8.8.8:53"}},
        {// Google (Plain)
                "sdns://AAcAAAAAAAAABzguOC44Ljg", {}},
        {// AdGuard DNS (DNS-over-TLS)
                "sdns://AwAAAAAAAAAAAAAPZG5zLmFkZ3VhcmQuY29t", {"8.8.8.8:53"}},
        {// DoT 1.1.1.1
                "sdns://AwAAAAAAAAAAAAAHMS4xLjEuMQ", {"8.8.8.8:53"}},
        {// Cloudflare DNS
                "https://1.1.1.1/dns-query", {}},
        {// AdGuard DNS (DNS-over-QUIC)
                "quic://dns.adguard-dns.com", {"8.8.8.8:53"}},
        {// AdGuard DNS (DNS-over-QUIC) custom port
                "quic://dns.adguard-dns.com:8853", {"8.8.8.8:53"}},
        {// AdGuard DNS (DNS-over-QUIC) stamp with only the port specified in server address field
                "sdns://BAAAAAAAAAAABDo4NTMAE2Rucy5hZGd1YXJkLWRucy5jb20", {"8.8.8.8:53"}},
};

#ifdef __linux__
#include <cstddef>
#include <dirent.h>

int count_open_fds() {
    DIR *dir = opendir("/proc/self/fd");
    if (dir == nullptr) {
        return -1;
    }

    int count = -3; // '.', '..', dir
    while (readdir(dir)) {
        count++;
    }

    (void) closedir(dir);

    return count;
}

// Bounded poll for the open-fd count to stabilize after a sequential run,
// replacing the former fixed 500 ms sleep. Lets closed sockets leave TIME_WAIT
// without slowing the offline path. No-op outside Linux.
static coro::Task<void> wait_for_fds_to_stabilize(EventLoop &loop, int baseline) {
    for (int i = 0; i < 50; ++i) { // up to ~250 ms total
        if (count_open_fds() <= baseline) {
            break;
        }
        co_await loop.co_sleep(Millis{5});
    }
    co_return;
}
#endif /* __linux__ */

// Always-on: plain UDP/TCP against the loopback server. Validates the real
// PlainUpstream transport + UpstreamFactory path with no internet. No
// inter-test sleep (nothing to rate-limit).
TEST_F(UpstreamTest, TestUpstreamsLocal) {
    const std::vector<UpstreamTestData> local_upstreams_data = {
            {local_udp(), {}, {}},   // plain UDP
            {local_tcp(), {}, {}},   // plain TCP
            {local_plain(), {}, {}}, // plain (no scheme), UDP-first
    };
#ifdef __linux__
    int fd_count_before = count_open_fds();
#endif
    ASSERT_NO_FATAL_FAILURE(co_await sequential_test(local_upstreams_data));
#ifdef __linux__
    co_await wait_for_fds_to_stabilize(*m_loop, fd_count_before);
    // If there was fd leak, new fd number will be different.
    // There can be extra fd for /dev/null writing.
    int fd_count_after = count_open_fds();
    ASSERT_TRUE(fd_count_before <= fd_count_after);
    ASSERT_TRUE(fd_count_after <= fd_count_before + 1);
#endif
}

// Always-on: DoT against the loopback TLS server. Exercises the real
// DotUpstream + TLS handshake against an in-process responder (the cert is
// accepted by TestCertificateVerifier{ACCEPT_ALL}). Replaces the former real-
// DoT entries (tls://1.1.1.1, tls://9.9.9.9:853, tls://dns.google,
// tls://one.one.one.one) so the default suite never dials public DoT.
TEST_F(UpstreamTest, TestUpstreamsDotLocal) {
    const std::vector<UpstreamTestData> local_dot_data = {
            {local_dot(), {}, {}}, // DoT, literal-IP loopback (bootstrapper bypassed)
    };
    ASSERT_NO_FATAL_FAILURE(co_await sequential_test(local_dot_data));
}

// Always-on: DoH against the loopback DoH server. Exercises the real
// DohUpstream + TLS + HTTP/2 path against an in-process responder (the cert is
// accepted by TestCertificateVerifier{ACCEPT_ALL}). Replaces the former real-
// DoH entries (dns9.quad9.net, dns.cloudflare.com, dns.google, 1.1.1.1, DoH
// stamps, credentialed DoH URLs/stamps) so the default suite never dials
// public DoH. All variants use a literal-IP loopback address so the
// bootstrapper is bypassed.
TEST_F(UpstreamTest, TestUpstreamsDohLocal) {
    const std::vector<UpstreamTestData> local_doh_data = {
            {local_doh(), {}, {}},                  // basic DoH URL
            {local_doh_url_with_creds(), {}, {}},   // credentialed DoH URL
            {local_doh_stamp(), {}, {}},            // DoH stamp (sdns://)
            {local_doh_stamp_with_creds(), {}, {}}, // credentialed DoH stamp
    };
    ASSERT_NO_FATAL_FAILURE(co_await sequential_test(local_doh_data));
}

// Always-on: DNSCrypt against loopback DNSCrypt responders (127.0.0.1).
// Exercises the real DnscryptUpstream + DNSCrypt handshake (cert fetch + key
// exchange + encrypted relay) against in-process servers returning a canned
// 8.8.8.8 A answer. Replaces the former real DNSCrypt entries (Cisco OpenDNS,
// AdGuard DNS, AdGuard Family) so the default suite never dials public
// DNSCrypt. Both supported crypto constructions are covered; each stamp uses a
// literal-IP loopback address so the bootstrapper is bypassed.
TEST_F(UpstreamTest, TestUpstreamsDnscryptLocal) {
    // make_loopback_a_reply has a default `ip` argument, so it must be wrapped
    // in a lambda (defaults are not applied through std::function).
    auto handler = [](const ldns_pkt &req) {
        return make_loopback_a_reply(req);
    };
    ag::test::LoopbackDnscryptServer server_salsa{handler};
    server_salsa.start();
    ag::test::LoopbackDnscryptServer server_chacha{handler, dnscrypt::CryptoConstruction::X_CHACHA_20_POLY_1305};
    server_chacha.start();
    const std::vector<UpstreamTestData> local_dnscrypt_data = {
            {server_salsa.stamp(), {}, {}},  // DNSCrypt, X_SALSA_20_POLY_1305
            {server_chacha.stamp(), {}, {}}, // DNSCrypt, X_CHACHA_20_POLY_1305
    };
    ASSERT_NO_FATAL_FAILURE(co_await sequential_test(local_dnscrypt_data));
}

// Always-on: DoQ and DoH3 against the loopback QUIC servers. Exercises the real
// DoqUpstream + DohUpstream (HTTP/3) transports + QUIC/TLS handshake against
// in-process responders (the cert is accepted by
// TestCertificateVerifier{ACCEPT_ALL}). Replaces the former real
// h3://cloudflare-dns.com, quic://dns.adguard-dns.com, and DoQ stamp entries
// so the default suite never dials public DoQ/DoH3. Both URL-based and
// stamp-based DoQ upstreams are tested; the DoH3 server handles GET ?dns=
// identically to the DoH server.
TEST_F(UpstreamTest, TestUpstreamsDoqDoh3Local) {
    const std::vector<UpstreamTestData> local_data = {
            {local_doh3(), {}, {}},      // DoH3 (h3://)
            {local_doq(), {}, {}},       // DoQ (quic://, literal IP)
            {local_doq_stamp(), {}, {}}, // DoQ stamp (sdns://)
    };
    ASSERT_NO_FATAL_FAILURE(co_await sequential_test(local_data));
}

// Real upstreams across all protocols. Only runs when
// DNSLIBS_INTEGRATION_TESTS is set; otherwise SKIPPED so the default suite
// never touches the public internet. (Offline loopback counterparts for each
// protocol family live in TestUpstreams{Local,DotLocal,DohLocal,DnscryptLocal,
// DoqDoh3Local}.)
TEST_F(UpstreamTest, TestUpstreamsIntegration) {
    REQUIRE_INTEGRATION();
#ifdef __linux__
    int fd_count_before = count_open_fds();
#endif
    ASSERT_NO_FATAL_FAILURE(co_await sequential_test(real_upstreams_data, DELAY_BETWEEN_REQUESTS));
#ifdef __linux__
    co_await wait_for_fds_to_stabilize(*m_loop, fd_count_before);
    int fd_count_after = count_open_fds();
    ASSERT_TRUE(fd_count_before <= fd_count_after);
    ASSERT_TRUE(fd_count_after <= fd_count_before + 1);
#endif
}

// DoT upstream bootstrapped via encrypted-DNS resolvers that still require real
// servers: a DoH bootstrap and DNSCrypt/DoT-stamp bootstraps. These cannot be
// reproduced against loopback until the DoH (Task 6) and DNSCrypt (Task 8)
// loopback responders exist, so they stay gated. The plain- and DoT-bootstrap
// rows are migrated to TestUpstreamDotBootstrapLocal (offline).
static const UpstreamTestData upstream_dot_bootstrap_integration_data[]{
        {
                "tls://one.one.one.one/",
                {"https://1.1.1.1/dns-query"},
        },
        {
                "tls://one.one.one.one/",
                {"sdns://AwAAAAAAAAAAAAAHMS4xLjEuMQ"}, // DoT 1.1.1.1
        },
        {
                "tls://one.one.one.one/",
                {"sdns://"
                 "AQIAAAAAAAAAETk0LjE0MC4xNC4xNDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_"
                 "OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20"}, // AdGuard DNS (DNSCrypt)
        },
};

TEST_F(UpstreamTest, TestUpstreamDotBootstrap) {
    REQUIRE_INTEGRATION();
    ASSERT_NO_FATAL_FAILURE(co_await sequential_test(upstream_dot_bootstrap_integration_data));
}

// Always-on: DoT upstream bootstrapped via loopback resolvers (plain DNS and
// DoT). Each resolver resolves the upstream hostname (localhost) to 127.0.0.1,
// so the DoT exchange lands on the in-process TLS server (m_loopback_tls). No
// public internet. The upstream uses a hostname (not a literal IP) so the
// bootstrapper is genuinely exercised.
TEST_F(UpstreamTest, TestUpstreamDotBootstrapLocal) {
    // Plain DNS bootstrap: resolves localhost -> 127.0.0.1.
    ag::test::LoopbackDnsServer plain_bootstrap{[](const ldns_pkt &req) {
        return make_loopback_a_reply(req, "127.0.0.1");
    }};
    plain_bootstrap.start();
    // DoT bootstrap: same resolver behavior, over TLS (cert accepted by the
    // fixture's TestCertificateVerifier{ACCEPT_ALL}).
    ag::test::LoopbackTlsServer dot_bootstrap{[](const ldns_pkt &req) {
        return make_loopback_a_reply(req, "127.0.0.1");
    }};
    dot_bootstrap.start();

    const std::string upstream_addr = AG_FMT("tls://localhost:{}", m_loopback_tls.port());
    const std::vector<UpstreamTestData> local_data = {
            {upstream_addr, {AG_FMT("127.0.0.1:{}", plain_bootstrap.port())}},
            {upstream_addr, {AG_FMT("tls://127.0.0.1:{}", dot_bootstrap.port())}},
    };
    ASSERT_NO_FATAL_FAILURE(co_await sequential_test(local_data));
}

// Always-on: plain DNS, DoT, and DoH against the loopback servers, succeeds
// offline. The DoT entry replaces the former real `tls://1.1.1.1` default-
// options check; the DoH entry replaces the former real DoH entries.
TEST_F(UpstreamTest, UpstreamDefaultOptionsLocal) {
    co_await m_loop->co_submit();
    for (const std::string &address : {local_udp(), local_tcp(), local_plain(), local_dot(), local_doh()}) {
        auto upstream_res = create_upstream({address, {}});
        ASSERT_FALSE(upstream_res.has_error())
                << "Failed to generate upstream from address " << address << ": " << upstream_res.error()->str();
        auto err = co_await check_upstream(*upstream_res.value(), address);
        ASSERT_FALSE(err) << *err;
    }
}

// Real `8.8.8.8` plain DNS with default options. Gated. (The DoT default-options
// check moved to UpstreamDefaultOptionsLocal against the loopback TLS server.)
TEST_F(UpstreamTest, UpstreamDefaultOptionsIntegration) {
    REQUIRE_INTEGRATION();
    co_await m_loop->co_submit();
    for (const std::string &address : {"8.8.8.8"}) {
        auto upstream_res = create_upstream({address, {}});
        ASSERT_FALSE(upstream_res.has_error())
                << "Failed to generate upstream from address " << address << ": " << upstream_res.error()->str();
        auto err = co_await check_upstream(*upstream_res.value(), address);
        ASSERT_FALSE(err) << *err;
    }
}

static const UpstreamTestData test_upstreams_invalid_bootstrap_data[]{
        {
                "tls://dns.adguard-dns.com",
                {"1.1.1.1:555", "8.8.8.8:53"},
        },
        {
                "tls://dns.adguard-dns.com:853",
                {"1.0.0.1", "8.8.8.8:535"},
        },
        {
                "https://dns.cloudflare.com/dns-query",
                {"8.8.8.1", "1.0.0.1"},
        },
        {
                "https://dns9.quad9.net:443/dns-query",
                {"1.2.3.4:79", "8.8.8.8:53"},
        },
        {
                "quic://dns.adguard-dns.com",
                {"1.1.1.1:555", "8.8.8.8:53"},
        },
        {
                // Cloudflare DNS (DoH)
                "sdns://AgcAAAAAAAAABzEuMC4wLjEAEmRucy5jbG91ZGZsYXJlLmNvbQovZG5zLXF1ZXJ5",
                {"8.8.8.8:53", "8.8.8.1:53"},
        },
        {
                // AdGuard DNS (DNS-over-TLS)
                "sdns://AwAAAAAAAAAAAAAPZG5zLmFkZ3VhcmQuY29t",
                {"1.2.3.4:55", "8.8.8.8"},
        },
};

// DoH and DoT upstreams with two bootstraps (only one is valid). These exercise
// the bootstrapper's "first success wins" fallback, which only applies to
// encrypted upstreams (DoT/DoH/DoQ) — plain upstreams bypass the bootstrapper.
// Gated; the offline loopback counterparts are in
// TestUpstreams{Dot,Doh,Doq}InvalidBootstrapLocal.
TEST_F(UpstreamTest, TestUpstreamsInvalidBootstrap) {
    REQUIRE_INTEGRATION();
    ASSERT_NO_FATAL_FAILURE(co_await sequential_test(test_upstreams_invalid_bootstrap_data));
}

// DoT upstream with two bootstraps (only one is valid), reproduced against
// loopback so the suite stays offline. The bootstrapper runs both resolvers in
// parallel and takes the first success; the dead loopback address fails fast
// while the good loopback resolver resolves the upstream hostname (localhost)
// to 127.0.0.1, lands the exchange on m_loopback_tls.
TEST_F(UpstreamTest, TestUpstreamsDotInvalidBootstrapLocal) {
    ag::test::LoopbackDnsServer good_bootstrap{[](const ldns_pkt &req) {
        return make_loopback_a_reply(req, "127.0.0.1");
    }};
    good_bootstrap.start();

    const std::string upstream_addr = AG_FMT("tls://localhost:{}", m_loopback_tls.port());
    const std::string good_addr = AG_FMT("127.0.0.1:{}", good_bootstrap.port());
    const std::vector<UpstreamTestData> local_data = {
            {upstream_addr, {"127.0.0.1:1", good_addr}},
            {upstream_addr, {"127.0.0.1:2", good_addr}},
    };
    ASSERT_NO_FATAL_FAILURE(co_await sequential_test(local_data));
}

// DoH upstream with two bootstraps (only one is valid), reproduced against
// loopback so the suite stays offline. The bootstrapper runs both resolvers in
// parallel and takes the first success; the dead loopback address fails fast
// while the good loopback resolver resolves the upstream hostname (localhost)
// to 127.0.0.1, landing the exchange on m_loopback_doh. Both a URL-based and
// a stamp-based DoH upstream are tested.
TEST_F(UpstreamTest, TestUpstreamsDohInvalidBootstrapLocal) {
    ag::test::LoopbackDnsServer good_bootstrap{[](const ldns_pkt &req) {
        return make_loopback_a_reply(req, "127.0.0.1");
    }};
    good_bootstrap.start();

    const std::string upstream_url = AG_FMT("https://localhost:{}/dns-query", m_loopback_doh.port());
    const std::string good_addr = AG_FMT("127.0.0.1:{}", good_bootstrap.port());
    // DoH stamp with a hostname provider_name so the bootstrapper is exercised.
    ServerStamp stamp{};
    stamp.proto = StampProtoType::DOH;
    stamp.server_addr_str = AG_FMT("127.0.0.1:{}", m_loopback_doh.port());
    stamp.provider_name = "localhost";
    stamp.path = "/dns-query";
    stamp.props = ServerInformalProperties{};
    const std::vector<UpstreamTestData> local_data = {
            {upstream_url, {"127.0.0.1:1", good_addr}},
            {stamp.str(), {"127.0.0.1:2", good_addr}},
    };
    ASSERT_NO_FATAL_FAILURE(co_await sequential_test(local_data));
}

// DoQ upstream with two bootstraps (only one is valid), reproduced against
// loopback so the suite stays offline. The bootstrapper runs both resolvers in
// parallel and takes the first success; the dead loopback address fails fast
// while the good loopback resolver resolves the upstream hostname (localhost)
// to 127.0.0.1, landing the exchange on m_loopback_doq. Replaces the former
// real quic://dns.adguard-dns.com row.
TEST_F(UpstreamTest, TestUpstreamsDoqInvalidBootstrapLocal) {
    ag::test::LoopbackDnsServer good_bootstrap{[](const ldns_pkt &req) {
        return make_loopback_a_reply(req, "127.0.0.1");
    }};
    good_bootstrap.start();

    const std::string upstream_addr = AG_FMT("quic://localhost:{}", m_loopback_doq.port());
    const std::string good_addr = AG_FMT("127.0.0.1:{}", good_bootstrap.port());
    const std::vector<UpstreamTestData> local_data = {
            {upstream_addr, {"127.0.0.1:1", good_addr}},
    };
    ASSERT_NO_FATAL_FAILURE(co_await sequential_test(local_data));
}

// Use invalid bootstrap to make sure it fails if tries to use it
static const std::initializer_list<std::string> invalid_bootstrap{"1.2.3.4:55"};

static const UpstreamTestData test_upstreams_with_server_ip_data[]{
        {"tls://dns.adguard-dns.com", invalid_bootstrap, Ipv4Address{94, 140, 14, 14}},
        {"https://dns.adguard-dns.com/dns-query", invalid_bootstrap, Ipv4Address{94, 140, 14, 14}},
        {"quic://dns.adguard-dns.com", invalid_bootstrap, Ipv4Address{94, 140, 14, 14}},
        {// AdGuard DNS DOH with the IP address specified
                "sdns://AgcAAAAAAAAADDk0LjE0MC4xNC4xNAATZG5zLmFkZ3VhcmQtZG5zLmNvbQovZG5zLXF1ZXJ5", invalid_bootstrap,
                {}},
        {// AdGuard DNS DOT with the IP address specified
                "sdns://AwAAAAAAAAAAEDk0LjE0MC4xNC4xNDo4NTMAE2Rucy5hZGd1YXJkLWRucy5jb20", invalid_bootstrap, {}},
};

// Encrypted upstreams (DoT/DoH/DoQ) with a resolved server IP. Gated; the
// offline loopback counterparts are in
// TestUpstreams{Dot,Doh,Doq}WithServerIpLocal.
TEST_F(UpstreamTest, TestUpstreamsWithServerIp) {
    REQUIRE_INTEGRATION();
    ASSERT_NO_FATAL_FAILURE(co_await sequential_test(test_upstreams_with_server_ip_data));
}

// DoT upstream with a resolved server IP, reproduced against loopback. With
// resolved_server_ip set, the bootstrapper is bypassed and DotUpstream connects
// directly to 127.0.0.1:<port> (the loopback TLS server), so the dead bootstrap
// is never used. Replaces the former real tls://dns.adguard-dns.com row.
TEST_F(UpstreamTest, TestUpstreamsWithServerIpDotLocal) {
    const std::string upstream_addr = AG_FMT("tls://localhost:{}", m_loopback_tls.port());
    const std::vector<UpstreamTestData> local_data = {
            {upstream_addr, {"127.0.0.1:1"}, Ipv4Address{127, 0, 0, 1}},
    };
    ASSERT_NO_FATAL_FAILURE(co_await sequential_test(local_data));
}

// DoH upstream with a resolved server IP, reproduced against loopback. With
// resolved_server_ip set, the bootstrapper is bypassed and DohUpstream connects
// directly to 127.0.0.1:<port> (the loopback DoH server), so the dead bootstrap
// is never used. Replaces the former real dns.adguard-dns.com DoH URL/stamp
// rows. Both a URL-based and a stamp-based DoH upstream are tested (the stamp
// encodes 127.0.0.1:<port> directly, so the bootstrap is also bypassed).
TEST_F(UpstreamTest, TestUpstreamsDohWithServerIpLocal) {
    const std::string upstream_url = AG_FMT("https://localhost:{}/dns-query", m_loopback_doh.port());
    const std::vector<UpstreamTestData> local_data = {
            {upstream_url, {"127.0.0.1:1"}, Ipv4Address{127, 0, 0, 1}},
            {local_doh_stamp(), {"127.0.0.1:1"}, {}},
    };
    ASSERT_NO_FATAL_FAILURE(co_await sequential_test(local_data));
}

// DoQ upstream with a resolved server IP, reproduced against loopback. A
// literal-IP loopback URL makes the bootstrapper short-circuit (no DNS lookup)
// so the dead bootstrap is never contacted, landing the exchange directly on
// m_loopback_doq. This replaces the former real
// quic://dns.adguard-dns.com row, which used resolved_server_ip to bypass
// DNS. (DoqUpstream::init hardcodes DEFAULT_DOQ_PORT when resolved_server_ip
// is set, so a literal-IP URL + dead bootstrap is the offline equivalent that
// preserves the bypass-bootstrap intent without requiring a fixed port.)
TEST_F(UpstreamTest, TestUpstreamsDoqWithServerIpLocal) {
    const std::string upstream_addr = AG_FMT("quic://127.0.0.1:{}", m_loopback_doq.port());
    const std::vector<UpstreamTestData> local_data = {
            {upstream_addr, {"127.0.0.1:1"}, {}},
    };
    ASSERT_NO_FATAL_FAILURE(co_await sequential_test(local_data));
}

struct DeadProxyFailure : UpstreamParamTest<std::tuple<std::string, OutboundProxySettings>> {};
#ifdef _WIN32
// On Windows connections to the dead proxy time out instead of being refused
TEST_P(DeadProxyFailure, DISABLED_FailedExchange) {
#else
TEST_P(DeadProxyFailure, FailedExchange) {
#endif
    co_await m_loop->co_submit();
    auto oproxy = std::make_unique<OutboundProxySettings>(std::get<1>(GetParam()));
    make_upstream_factory(oproxy.get());
    // Target is a dead loopback address; the outbound proxy (127.0.0.1:42) is
    // also dead, so the exchange fails fast with no internet access.
    auto upstream_res = create_upstream({std::get<0>(GetParam()), {}});
    ASSERT_FALSE(upstream_res.has_error()) << upstream_res.error()->str();
    auto err = co_await check_upstream(*upstream_res.value(), std::get<0>(GetParam()));
    ASSERT_TRUE(err.has_value());
}

INSTANTIATE_TEST_SUITE_P(TcpOnlyProxy, DeadProxyFailure,
        ::testing::Combine(::testing::Values("tcp://127.0.0.1:1"),
                ::testing::Values(OutboundProxySettings{OutboundProxyProtocol::HTTP_CONNECT, "127.0.0.1", 42},
                        OutboundProxySettings{OutboundProxyProtocol::HTTPS_CONNECT, "127.0.0.1", 42},
                        OutboundProxySettings{OutboundProxyProtocol::SOCKS4, "127.0.0.1", 42},
                        OutboundProxySettings{OutboundProxyProtocol::SOCKS5, "127.0.0.1", 42})));

INSTANTIATE_TEST_SUITE_P(UdpProxy, DeadProxyFailure,
        ::testing::Combine(::testing::Values("127.0.0.1:1"),
                ::testing::Values(OutboundProxySettings{OutboundProxyProtocol::SOCKS5_UDP, "127.0.0.1", 42})));

// Disabled: a stress test against real servers. Kept disabled (so it never
// runs in the default suite) rather than gated, to preserve its original
// intent for manual runs.
TEST_F(UpstreamTest, DISABLED_ConcurrentRequests) {
    co_await m_loop->co_submit();
    using namespace std::chrono_literals;
    using namespace concat_err_string;
    static constexpr size_t REQUESTS_NUM = 128;
    static constexpr size_t WORKERS_NUM = 16;
    static const UpstreamOptions opts{
            .address = "https://dns.cloudflare.com/dns-query",
            //        .address = "quic://dns.adguard-dns.com:8853", // Uncomment for test DOQ upstream
            .bootstrap = {"8.8.8.8", "1.1.1.1"},
            //        .resolved_server_ip = IPV4_ADDRESS_SIZE{104, 19, 199, 29}, // Uncomment for test this server IP
            //        .resolved_server_ip = IPV6_ADDRESS_SIZE{0x26, 0x06, 0x47, 0x00, 0x30, 0x0a, 0x00, 0x00, 0x00,
            //        0x00, 0x00, 0x00, 0x68, 0x13, 0xc7, 0x1d},  // Uncomment for test this server IP
    };
    auto upstream_res = create_upstream(opts, 5s);
    ASSERT_FALSE(upstream_res.has_error()) << upstream_res.error()->str();
    co_await parallel_test_basic_n(
            *m_loop, WORKERS_NUM, [upstream = upstream_res->get()](size_t i) -> coro::Task<TestError> {
                TestError result_err;
                for (size_t j = 0; j < REQUESTS_NUM; ++j) {
                    ldns_pkt_ptr pkt = create_test_message();
                    auto reply = co_await upstream->exchange(pkt.get());
                    if (reply.has_error()) {
                        result_err += AG_FMT("Upstream i = {} reply error: {}", i, reply.error()->str());
                        continue;
                    }
                    if (!reply) {
                        result_err += "Upstream reply is null";
                        continue;
                    }
                    result_err += assert_response(*reply.value());
                }
                co_return result_err;
            });
}

// Disabled: a stress test against a real DoQ server. Kept disabled (so it
// never runs in the default suite) rather than gated.
TEST_F(UpstreamTest, DISABLED_DoqEasyTest) {
    co_await m_loop->co_submit();
    for (int i = 0; i < 1000; ++i) {
        using namespace std::chrono_literals;
        using namespace concat_err_string;
        static const UpstreamOptions opts{.address = "quic://dns.adguard-dns.com:8853", .bootstrap = {"8.8.8.8"}};
        auto upstream_res = create_upstream(opts, 5s);
        ASSERT_FALSE(upstream_res.has_error()) << upstream_res.error()->str();

        ldns_pkt_ptr pkt = create_test_message();

        auto reply_res = co_await upstream_res.value()->exchange(pkt.get());
        ASSERT_FALSE(reply_res.has_error()) << reply_res.error()->str();
        ASSERT_NE(reply_res.value(), nullptr);
    }
}

struct UpstreamIvalidFingerprintTest : UpstreamParamTest<UpstreamOptions> {};

static const UpstreamOptions test_options_with_invalid_fingerprint_data[]{
        {
                .address = "tls://127.0.0.1:853",
                .fingerprints = {"INVALIDFINGERPRINT!"},
        },
        {
                .address = "https://127.0.0.1/dns-query",
                .fingerprints = {"INVALIDFINGERPRINT!"},
        },
        {
                .address = "quic://127.0.0.1:8853",
                .fingerprints = {"INVALIDFINGERPRINT!"},
        },
};

// No exchange happens: create_upstream() fails at fingerprint parsing, before
// any network I/O or address resolution. Pointing the addresses at loopback
// keeps the suite offline.
TEST_P(UpstreamIvalidFingerprintTest, TestUpstreamIvalidFingerprint) {
    co_await m_loop->co_submit();
    const auto &op = GetParam();
    auto upstream_res = create_upstream(op);
    ASSERT_TRUE(upstream_res.has_error()) << "Expected that create_upstream return error";
}

INSTANTIATE_TEST_SUITE_P(UpstreamIvalidFingerprintTest, UpstreamIvalidFingerprintTest,
        testing::ValuesIn(test_options_with_invalid_fingerprint_data));

} // namespace ag::dns::upstream::test
