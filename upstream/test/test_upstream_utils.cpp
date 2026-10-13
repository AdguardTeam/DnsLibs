#include "dns/upstream/upstream_utils.h"
#include "gtest/gtest.h"
#include <magic_enum/magic_enum.hpp>

#include "dns_test_helpers.h"
#include "loopback_dns_server.h"
#include "loopback_tls_server.h"
#include "test_certificates.h"

using namespace std::chrono_literals;

static constexpr auto timeout = 500ms;

namespace ag::dns::upstream::test {

struct UpstreamUtilsTest : ::testing::Test {
protected:
    void SetUp() override {
        Logger::set_log_level(LogLevel::LOG_LEVEL_TRACE);
    }
};

// Dead loopback port: nothing is listening, so the exchange fails fast with no
// internet access (replaces the former routable-but-dead 123.12.32.1:1493 which
// relied on a slow timeout).
TEST_F(UpstreamUtilsTest, InvalidUpstreamOnline) {
    auto err = dns::test_upstream({"udp://127.0.0.1:1", {}}, timeout, false, nullptr, false);
    ASSERT_TRUE(err) << "Cannot be successful";
}

TEST_F(UpstreamUtilsTest, ValidUpstreamOnline) {
    // In-process loopback responder: replies with one A answer so that
    // test_upstream()'s "at least one answer" check passes offline.
    ag::test::LoopbackDnsServer server([](const ldns_pkt &req) -> ldns_pkt_ptr {
        ldns_pkt_ptr reply = ag::test::make_base_reply(req);
        if (const ldns_rr *question = ldns_rr_list_rr(ldns_pkt_question(&req), 0); question != nullptr) {
            ag::test::add_a_answer(reply.get(), question);
        }
        return reply;
    });
    server.start();
    auto err = dns::test_upstream({server.address(ag::utils::TP_UDP), {}}, 10 * timeout, false, nullptr, false);
    ASSERT_FALSE(err) << "Cannot fail: " << err->str();
    server.stop();
}

// DoT with two bootstraps (only one is valid), reproduced against loopback. The
// first bootstrap is a dead loopback (fails fast); the second is a loopback DNS
// resolver that resolves the upstream hostname (localhost) to 127.0.0.1, so the
// DoT exchange lands on the in-process TLS server. The cert is accepted via the
// accept-all verification callback.
TEST_F(UpstreamUtilsTest, ValidUpstreamTlsTwoBootstraps) {
    // Good bootstrap: resolves any host -> 127.0.0.1 (so localhost resolves to
    // the loopback TLS server).
    ag::test::LoopbackDnsServer good_bootstrap{[](const ldns_pkt &req) -> ldns_pkt_ptr {
        ldns_pkt_ptr reply = ag::test::make_base_reply(req);
        if (const ldns_rr *question = ldns_rr_list_rr(ldns_pkt_question(&req), 0); question != nullptr) {
            ldns_rr *answer = ldns_rr_new();
            ldns_rr_set_owner(answer, ldns_rdf_clone(ldns_rr_owner(question)));
            ldns_rr_set_ttl(answer, 300);
            ldns_rr_set_type(answer, LDNS_RR_TYPE_A);
            ldns_rr_set_class(answer, LDNS_RR_CLASS_IN);
            ldns_rr_push_rdf(answer, ldns_rdf_new_frm_str(LDNS_RDF_TYPE_A, "127.0.0.1"));
            ldns_pkt_push_rr(reply.get(), LDNS_SECTION_ANSWER, answer);
        }
        return reply;
    }};
    good_bootstrap.start();
    // Loopback DoT responder: returns one A answer so test_upstream()'s
    // "at least one answer" check passes offline.
    ag::test::LoopbackTlsServer tls_server{[](const ldns_pkt &req) -> ldns_pkt_ptr {
        ldns_pkt_ptr reply = ag::test::make_base_reply(req);
        if (const ldns_rr *question = ldns_rr_list_rr(ldns_pkt_question(&req), 0); question != nullptr) {
            ag::test::add_a_answer(reply.get(), question);
        }
        return reply;
    }};
    tls_server.start();

    auto err = dns::test_upstream(
            {AG_FMT("tls://localhost:{}", tls_server.port()),
                    {"127.0.0.1:1", AG_FMT("127.0.0.1:{}", good_bootstrap.port())}},
            10 * timeout, false,
            [](const CertificateVerificationEvent &) {
                return std::nullopt;
            },
            false);
    ASSERT_FALSE(err) << "Cannot fail: " << err->str();

    tls_server.stop();
    good_bootstrap.stop();
}

TEST_F(UpstreamUtilsTest, InvalidUpstreamOfflineLooksValid) {
    // offline=true skips the exchange, so a loopback dead address is enough.
    auto err = dns::test_upstream({"127.0.0.1:1", {}}, timeout, false, nullptr, true);
    ASSERT_FALSE(err) << "Cannot fail: " << err->str();
}

TEST_F(UpstreamUtilsTest, InvalidUpstreamOfflineUnknownScheme) {
    auto err = dns::test_upstream({"unk://127.0.0.1:1", {}}, timeout, false, nullptr, true);
    ASSERT_TRUE(err) << "Cannot be successful";
}

TEST_F(UpstreamUtilsTest, ValidUpstreamMixedCase) {
    // offline=true skips the exchange, so the bootstrap is never resolved; a
    // loopback literal keeps the suite offline. The mixed-case hostname still
    // exercises the URL hostname-lowercasing path.
    auto err = dns::test_upstream(
            {"Https://Mixed-Case-Host.Example/dns-query", {"127.0.0.1"}}, timeout, false, nullptr, true);
    ASSERT_FALSE(err) << "Cannot fail: " << err->str();
}

TEST_F(UpstreamUtilsTest, PrivateNetworkAddress) {
    const std::vector<std::pair<std::string_view, bool>> cases = {
            // RFC 1918 private networks
            {"10.0.0.0", true},
            {"10.255.255.255", true},
            {"172.16.0.1", true},
            {"172.31.255.255", true},
            {"192.168.0.1", true},
            {"192.168.255.255", true},
            // Link-local addresses
            {"169.254.1.1", true},
            // Unique local and link-local IPv6
            {"fc00::1", true},
            {"fd12:3456:789a::1", true},
            {"fe80::1", true},
            // IPv4-mapped IPv6
            {"::ffff:192.168.1.1", true},
            {"::ffff:10.0.0.1", true},
            // Loopback addresses are not private networks
            {"127.0.0.1", false},
            {"127.255.255.255", false},
            {"::1", false},
            {"::ffff:127.0.0.1", false},
            // Globally routable addresses
            {"8.8.8.8", false},
            {"1.1.1.1", false},
            {"172.15.255.255", false},
            {"172.32.0.0", false},
            {"192.169.0.1", false},
            {"2001:4860:4860::8888", false},
            {"::ffff:8.8.8.8", false},
    };
    for (const auto &[address, expected] : cases) {
        EXPECT_EQ(is_private_network_address(SocketAddress{address, 53}), expected) << address;
    }
    // An address that is not an IP address at all is not in a private network either.
    EXPECT_FALSE(is_private_network_address(SocketAddress{}));
}

} // namespace ag::dns::upstream::test
