// Always-on upstream tests: protocol exchanges, truncation fallback, and
// bootstrap behavior against in-process loopback servers (fully offline), plus
// a few gated real-network counterparts. Shared infrastructure comes from
// upstream_test_fixture.h.

#include "upstream_test_fixture.h"

namespace ag::dns::upstream::test {

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
    auto errs = co_await parallel_run_n(count, [&](size_t index) -> coro::Task<TestError> {
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
                "sdns://AgcAAAAAAAAABzEuMC4wLjEAEmRucy5jbG91ZGZsYXJlLmNvbQovZG5zLXF1ZXJ5", invalid_bootstrap, {}},
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

} // namespace ag::dns::upstream::test
