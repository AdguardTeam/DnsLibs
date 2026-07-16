#include "common/logger.h"
#include "common/parallel.h"
#include <gtest/gtest.h>
#include <ldns/ldns.h>

#include "../dns64.h"
#include "dns_test_helpers.h"
#include "loopback_dns_server.h"

namespace ag::dns::dns64::test {

static Logger logger{"Dns64Test"};

// A loopback DNS64 responder. It answers AAAA queries for the well-known host
// `ipv4only.arpa` with two DNS64-synthesized addresses carrying the NAT64 prefix
// `64:ff9b::` (one per well-known IPv4 address, 192.0.0.170/171). This is exactly
// the shape `dns64::discover_prefixes` parses to extract the prefix, so the test
// runs deterministically on any host — IPv6-capable or not — without touching the
// public internet.
static ag::test::LoopbackDnsServer make_dns64_server() {
    return ag::test::LoopbackDnsServer([](const ldns_pkt &req) -> ldns_pkt_ptr {
        ldns_pkt_ptr reply = ag::test::make_base_reply(req);
        const ldns_rr *question = ldns_rr_list_rr(ldns_pkt_question(&req), 0);
        if (question != nullptr) {
            for (const char *ip6 : {"64:ff9b::192.0.0.170", "64:ff9b::192.0.0.171"}) {
                ldns_rr *aaaa = ldns_rr_new();
                ldns_rr_set_owner(aaaa, ldns_rdf_clone(ldns_rr_owner(question)));
                ldns_rr_set_ttl(aaaa, 300);
                ldns_rr_set_type(aaaa, LDNS_RR_TYPE_AAAA);
                ldns_rr_set_class(aaaa, LDNS_RR_CLASS_IN);
                ldns_rr_push_rdf(aaaa, ldns_rdf_new_frm_str(LDNS_RDF_TYPE_AAAA, ip6));
                ldns_pkt_push_rr(reply.get(), LDNS_SECTION_ANSWER, aaaa);
            }
        }
        return reply;
    });
}

TEST(Dns64Test, TestDns64Discovery) {
    using namespace std::chrono_literals;

    ag::test::LoopbackDnsServer dns64_server = make_dns64_server();
    dns64_server.start();

    EventLoopPtr loop = EventLoop::create();
    loop->start();
    SocketFactory socket_factory({*loop});
    UpstreamFactory upstream_factory({.loop = *loop, .socket_factory = &socket_factory, .timeout = 5000ms});
    const auto upstream_res = upstream_factory.create_upstream({.address = dns64_server.address(ag::utils::TP_UDP)});
    ASSERT_FALSE(upstream_res.has_error()) << upstream_res.error()->str();
    auto &upstream = upstream_res.value();

    const auto prefs_res =
            coro::to_future([](EventLoop &loop, const UpstreamPtr &upstream) -> coro::Task<DiscoveryResult> {
                co_await loop.co_submit();
                co_return co_await dns64::discover_prefixes(upstream);
            }(*loop, upstream))
                    .get();

    ASSERT_FALSE(prefs_res.has_error()) << prefs_res.error()->str();
    auto &prefs = prefs_res.value();

    ASSERT_FALSE(prefs.empty()) << "No Pref64::/n found";

    const std::set<Uint8Vector> prefs_set(prefs.cbegin(), prefs.cend());
    ASSERT_EQ(prefs.size(), prefs_set.size()) << "Found prefixes are not unique";

    // The crafted AAAA answers encode the NAT64 prefix 64:ff9b::/96, i.e. the
    // leading 12 bytes {0x00, 0x64, 0xff, 0x9b, 0x00...} of the synthesized
    // addresses. discover_prefixes must return exactly that prefix.
    const Uint8Vector EXPECTED_PREF64 = {0x00, 0x64, 0xff, 0x9b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    ASSERT_EQ(1u, prefs.size());
    ASSERT_EQ(EXPECTED_PREF64, prefs[0]);

    loop->stop();
    loop->join();
}

static void check_synth(const Uint8View pref64, const Uint8View ip4, const Uint8Array<16> &expect_result) {
    auto res = dns64::synthesize_ipv4_embedded_ipv6_address(pref64, ip4);
    ASSERT_FALSE(res.has_error()) << res.error()->str();
    ASSERT_EQ(res.value(), expect_result);
}

TEST(Dns64Test, TestIpv6Synthesis) {
    constexpr uint8_t ip4[] = {1, 2, 3, 4};
    const Uint8View ip4_v{ip4, std::size(ip4)};

    constexpr uint8_t pref[] = {5, 5, 5, 5, 5, 5, 5, 5, 0, 5, 5, 5};

    constexpr Uint8Array<16> expect_4 = {5, 5, 5, 5, 1, 2, 3, 4, 0};             // rest is zeroes
    constexpr Uint8Array<16> expect_5 = {5, 5, 5, 5, 5, 1, 2, 3, 0, 4};          // rest is zeroes
    constexpr Uint8Array<16> expect_6 = {5, 5, 5, 5, 5, 5, 1, 2, 0, 3, 4};       // rest is zeroes
    constexpr Uint8Array<16> expect_7 = {5, 5, 5, 5, 5, 5, 5, 1, 0, 2, 3, 4};    // rest is zeroes
    constexpr Uint8Array<16> expect_8 = {5, 5, 5, 5, 5, 5, 5, 5, 0, 1, 2, 3, 4}; // rest is zeroes
    constexpr Uint8Array<16> expect_12 = {5, 5, 5, 5, 5, 5, 5, 5, 0, 5, 5, 5, 1, 2, 3, 4};

    // Check allowed pref lengths
    check_synth({pref, 4}, ip4_v, expect_4);
    check_synth({pref, 5}, ip4_v, expect_5);
    check_synth({pref, 6}, ip4_v, expect_6);
    check_synth({pref, 7}, ip4_v, expect_7);
    check_synth({pref, 8}, ip4_v, expect_8);
    check_synth({pref, 12}, ip4_v, expect_12);

    // Check disallowed pref length...
    auto result_10 = dns64::synthesize_ipv4_embedded_ipv6_address({pref, 10}, ip4_v);
    ASSERT_TRUE(result_10.has_error());
}

} // namespace ag::dns::dns64::test
