#include "dns/upstream/upstream_utils.h"
#include "gtest/gtest.h"
#include <magic_enum/magic_enum.hpp>

#include "dns_test_helpers.h"
#include "integration_test_guard.h"
#include "loopback_dns_server.h"

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

// DoT with two bootstraps (only one is valid). Requires a real TLS server, so
// it is gated. Uses a stub verifier b/c certificate verification is not part of
// the tested logic and would fail on platforms where it is unsupported by
// ag::default_verifier.
TEST_F(UpstreamUtilsTest, ValidUpstreamTlsTwoBootstraps) {
    REQUIRE_INTEGRATION();
    auto err = dns::test_upstream(
            {"tls://1.1.1.1", {"1.2.3.4", "8.8.8.8"}}, 10 * timeout, false,
            [](const CertificateVerificationEvent &) {
                return std::nullopt;
            },
            false);
    ASSERT_FALSE(err) << "Cannot fail: " << err->str();
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

} // namespace ag::dns::upstream::test
