// Validation tests: upstream options that MUST be rejected, at create time
// (malformed addresses, bad auth, invalid fingerprints) or at exchange time
// (dead DoH/DoT targets). Shared infrastructure comes from
// upstream_test_fixture.h.

#include "upstream_test_fixture.h"

namespace ag::dns::upstream::test {

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
