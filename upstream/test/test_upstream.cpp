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
#include "dns/net/default_verifier.h"
#include "dns/upstream/upstream.h"
#include "dns/upstream/upstream_utils.h"
#ifdef __ANDROID__
#include "android_res_api.h"
#endif

#include "dns_test_helpers.h"
#include "integration_test_guard.h"
#include "loopback_dns_server.h"

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

// Builds a canned A reply echoing the request's qname with rdata 8.8.8.8, so
// that assert_response() (which expects exactly one A answer == 8.8.8.8) passes
// against the loopback server with no internet access.
static ldns_pkt_ptr make_loopback_a_reply(const ldns_pkt &req) {
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
    ldns_rr_push_rdf(answer, ldns_rdf_new_frm_str(LDNS_RDF_TYPE_A, "8.8.8.8"));
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
    }

    void TearDown() override {
        m_loopback.stop();
        m_loop->stop();
        m_loop->join();
    }

    void make_upstream_factory(OutboundProxySettings *oproxy = nullptr) {
        struct SocketFactory::Parameters sf_parameters = {.loop = *m_loop};
#ifndef _WIN32
        sf_parameters.verifier = std::make_unique<DefaultVerifier>();
#else
        sf_parameters.verifier = std::make_unique<ApplicationVerifier>([](const CertificateVerificationEvent &) {
            return std::nullopt;
        });
#endif

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

// These combos rely on real domain names and real bootstrap resolution/TLS
// servers. The offline loopback server cannot reproduce them (a loopback
// plain upstream bypasses the bootstrapper entirely), so they are gated.
TEST_F(UpstreamTest, UseUpstreamWithWrongOptions) {
    REQUIRE_INTEGRATION();
    co_await m_loop->co_submit();
    static const UpstreamOptions OPTIONS[]{
            // non existent domain, valid bootstrap
            {"https://qwer.zxcv.asdf.", {"8.8.8.8"}},
            // existent domain, invalid bootstrap
            {"https://dns.adguard-dns.com/dnsquery", {"4.3.2.1"}},
            // DoT
            {"tls://one.one.two.asdf.", {"8.8.8.8"}},    // invalid/valid
            {"tls://one.one.one.one", {"4.3.2.1"}},      // valid/invalid
            {"tls://one.one.one.one:1234", {"8.8.8.8"}}, // invalid/valid
    };

    for (const UpstreamOptions &options : OPTIONS) {
        auto upstream_res = create_upstream(options);
        ASSERT_FALSE(upstream_res.has_error()) << upstream_res.error()->str();

        ldns_pkt_ptr msg = create_test_message();
        auto reply_res = co_await upstream_res.value()->exchange(msg.get());
        ASSERT_TRUE(reply_res.has_error()) << "Expected this upstream to error out: " << options.address;
    }
}

// Tests DoT bootstrap timeout against a real address. A loopback reformulation
// would require a loopback TLS server, which is out of scope.
TEST_F(UpstreamTest, TestBootstrapTimeout) {
    REQUIRE_INTEGRATION();
    using namespace std::chrono_literals;
    using namespace concat_err_string;
    static constexpr auto timeout = 100ms;
    static constexpr size_t count = 10;
    co_await m_loop->co_submit();
    auto errs = co_await parallel_run_n(*m_loop, count, [&](size_t index) -> coro::Task<TestError> {
        infolog(logger, "Start {}", index);
        // Specifying some wrong port instead so that bootstrap DNS timed out for sure
        auto upstream_res = create_upstream({"tls://one.one.one.one", {"8.8.8.8:555"}}, timeout);
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

// Real DNSCrypt server: the truncation handling for DNSCrypt can't be
// reproduced against loopback (it requires the DNSCrypt handshake).
TEST_F(UpstreamTest, DnsTruncatedDnscryptIntegration) {
    REQUIRE_INTEGRATION();
    co_await m_loop->co_submit();
    static constexpr std::string_view address =
            "sdns://"
            "AQIAAAAAAAAAETk0LjE0MC4xNC4xNDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_"
            "OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20";
    auto upstream_res = create_upstream({std::string(address), {}}, Secs(5));
    ASSERT_FALSE(upstream_res.has_error()) << "Error while creating an upstream: " << upstream_res.error()->str();
    auto request = dnscrypt::create_request_ldns_pkt(
            LDNS_RR_TYPE_TXT, LDNS_RR_CLASS_IN, LDNS_RD, "unit-test2.dns.adguard-dns.com.", std::nullopt);
    ldns_pkt_set_random_id(request.get());
    auto res = co_await upstream_res.value()->exchange(request.get());
    ASSERT_FALSE(res.has_error()) << "Error while making a request: " << res.error()->str();
    ASSERT_FALSE(ldns_pkt_tc(res->get())) << "Response must NOT be truncated";
}

// Integration-only: real DoT/DoH/DoH3/DoQ/DNSCrypt upstreams. The point of
// testing these protocols is the real handshake, which a loopback plain DNS
// server can't validate. Gated so the default suite stays offline.
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

// Real DoT/DoH/DoH3/DoQ/DNSCrypt upstreams. Only runs when
// DNSLIBS_INTEGRATION_TESTS is set; otherwise SKIPPED so the default suite
// never touches the public internet.
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

static const UpstreamTestData upstream_dot_bootstrap_test_data[]{
        {
                "tls://one.one.one.one/",
                {"tls://1.1.1.1"},
        },
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

// Real DoT/DoH/DNSCrypt bootstrap. Gated; a loopback reformulation would
// require a loopback TLS server (out of scope).
TEST_F(UpstreamTest, TestUpstreamDotBootstrap) {
    REQUIRE_INTEGRATION();
    ASSERT_NO_FATAL_FAILURE(co_await sequential_test(upstream_dot_bootstrap_test_data));
}

// Always-on: plain DNS against the loopback server, succeeds offline.
TEST_F(UpstreamTest, UpstreamDefaultOptionsLocal) {
    co_await m_loop->co_submit();
    for (const std::string &address : {local_udp(), local_tcp(), local_plain()}) {
        auto upstream_res = create_upstream({address, {}});
        ASSERT_FALSE(upstream_res.has_error())
                << "Failed to generate upstream from address " << address << ": " << upstream_res.error()->str();
        auto err = co_await check_upstream(*upstream_res.value(), address);
        ASSERT_FALSE(err) << *err;
    }
}

// Real `tls://1.1.1.1` and `8.8.8.8` with default options. Gated.
TEST_F(UpstreamTest, UpstreamDefaultOptionsIntegration) {
    REQUIRE_INTEGRATION();
    co_await m_loop->co_submit();
    for (const std::string &address : {"tls://1.1.1.1", "8.8.8.8"}) {
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
// encrypted upstreams (DoT/DoH/DoQ) — plain upstreams bypass the bootstrapper
// and can't be reformulated against loopback. Gated.
TEST_F(UpstreamTest, TestUpstreamsInvalidBootstrap) {
    REQUIRE_INTEGRATION();
    ASSERT_NO_FATAL_FAILURE(co_await sequential_test(test_upstreams_invalid_bootstrap_data));
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

// Encrypted upstreams (DoT/DoH/DoQ) with a resolved server IP. The server_ip
// path can't be reproduced against a plain loopback DNS server (it requires a
// loopback TLS server, out of scope). Gated.
TEST_F(UpstreamTest, TestUpstreamsWithServerIp) {
    REQUIRE_INTEGRATION();
    ASSERT_NO_FATAL_FAILURE(co_await sequential_test(test_upstreams_with_server_ip_data));
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
