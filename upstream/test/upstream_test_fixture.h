#pragma once

// Shared test infrastructure for the upstream test suite. The `UpstreamTest`
// fixture (event loop + socket factory + the six in-process loopback responders
// + the local_*() address helpers + create_upstream()) and the free helpers it
// depends on live here so they can be split across several test binaries
// (test_upstream / test_upstream_validation / test_upstream_integration) without
// duplication.
//
// Each `add_unit_test` target is a separate executable that includes this header
// exactly once, so the definitions use `inline` (functions/variables) and
// `inline constexpr` (constants): this keeps the header self-contained, avoids
// ODR violations, and -- importantly -- avoids `-Wunused-function` /
// `-Wunused-const-variable` in the binaries that don't use every helper (only
// `static` / anonymous-namespace definitions trigger those warnings).

#include <array>
#include <atomic>
#include <csignal>
#include <cstring>
#include <functional>
#include <future>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <thread>
#include <vector>

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

inline constexpr Secs DEFAULT_TIMEOUT(10);
// Only used on the integration path (real servers, rate-limited). The offline
// path (loopback) needs no delay between requests.
inline constexpr Millis DELAY_BETWEEN_REQUESTS{500};
inline constexpr int INTEGRATION_MAX_ATTEMPTS = 3;

using TestError = std::optional<std::string>;

struct Init {
    Init() {
#ifdef SIGPIPE
        std::signal(SIGPIPE, SIG_IGN);
#endif
    }
};
inline Init init_;

inline Logger logger{"test_upstream"};

namespace concat_err_string {

inline TestError &operator+=(TestError &result, const TestError &err) {
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

inline ldns_pkt_ptr create_test_message() {
    ldns_pkt *pkt = ldns_pkt_query_new(
            ldns_dname_new_frm_str("google-public-dns-a.google.com."), LDNS_RR_TYPE_A, LDNS_RR_CLASS_IN, LDNS_RD);
    // Atomic so concurrent callers (e.g. DISABLED_ConcurrentRequests) don't race
    // on the query-ID counter, which would yield duplicate/undefined IDs.
    static std::atomic<size_t> id = 0;
    ldns_pkt_set_id(pkt, id.fetch_add(1, std::memory_order_relaxed));
    return ldns_pkt_ptr(pkt);
}

[[nodiscard]] inline TestError assert_response(const ldns_pkt &reply) {
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

[[nodiscard]] inline coro::Task<TestError> check_upstream(Upstream &upstream, const std::string &addr) {
    auto req = create_test_message();
    auto reply = co_await upstream.exchange(req.get());
    if (reply.has_error()) {
        co_return AG_FMT("Couldn't talk to upstream {}: {}", addr, reply.error()->str());
    }
    co_return assert_response(*reply.value());
}

inline coro::Task<void> check_all_results(const std::vector<TestError> &errors) {
    using namespace concat_err_string;
    TestError err;
    for (auto &error : errors) {
        err += error;
    }
    ASSERT_FALSE(err) << *err;
}

template <typename F>
auto parallel_run_n(size_t count, const F &f) {
    auto all_of_awaitable = parallel::all_of<TestError>();
    for (size_t i = 0; i != count; i++) {
        all_of_awaitable.add(f(i));
    }
    return all_of_awaitable;
}

template <typename F>
coro::Task<void> parallel_test_basic_n(EventLoop &loop, size_t count, const F &f) {
    co_await loop.co_submit();
    auto results = co_await parallel_run_n(count, f);
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
inline ldns_pkt_ptr make_loopback_a_reply(const ldns_pkt &req, std::string_view ip = "8.8.8.8") {
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
    // `max_attempts` retries a failed exchange with a fresh upstream/connection
    // so a transient real-server failure doesn't fail the suite; the offline
    // path leaves it at 1 so a genuine local regression fails immediately.
    coro::Task<void> sequential_test(
            std::span<const UpstreamTestData> test_data, Millis delay_between = Millis{0}, int max_attempts = 1) {
        for (const UpstreamTestData &data : test_data) {
            infolog(logger, "Testing upstream: {}", data.address);

#ifdef __ANDROID__
            // Skip system:// tests if Android API is not available
            if (data.address.starts_with("system://")) {
                if (!AndroidResApi::is_available()) {
                    infolog(logger, "Skipping system:// test - Android API not available");
                    continue;
                }
            }
#endif

            TestError error;
            for (int attempt = 1; attempt <= max_attempts; ++attempt) {
                // Delay before each attempt (including retries) to respect the
                // real servers' rate limits; no-op on the offline path.
                if (delay_between.count() > 0) {
                    std::this_thread::sleep_for(delay_between);
                }
                auto upstream_res = create_upstream({data.address, data.bootstrap, data.server_ip});
                ASSERT_FALSE(upstream_res.has_error()) << AG_FMT(
                        "Failed to generate upstream from address {}: {}", data.address, upstream_res.error()->str());
                error = coro::to_future(check_upstream_internal(std::move(upstream_res.value()), data.address)).get();
                if (!error) {
                    break;
                }
                if (attempt < max_attempts) {
                    infolog(logger, "Upstream {} attempt {}/{} failed, retrying: {}", data.address, attempt,
                            max_attempts, *error);
                }
            }
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

#ifdef __linux__
#include <cstddef>
#include <dirent.h>

inline int count_open_fds() {
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
inline coro::Task<void> wait_for_fds_to_stabilize(EventLoop &loop, int baseline) {
    for (int i = 0; i < 50; ++i) { // up to ~250 ms total
        if (count_open_fds() <= baseline) {
            break;
        }
        co_await loop.co_sleep(Millis{5});
    }
    co_return;
}
#endif /* __linux__ */

} // namespace ag::dns::upstream::test
