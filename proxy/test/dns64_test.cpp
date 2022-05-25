#include "common/logger.h"
#include <gtest/gtest.h>
#include <ldns/ldns.h>

#include "../../upstream/test/test_utils.h"
#include "../dns64.h"

namespace ag::dns64::test {

static constexpr auto DNS64_SERVER_ADDR = "2001:4860:4860::6464";

static Logger logger{"Dns64Test"};

TEST(Dns64Test, TestDns64Discovery) {
    if (!test_ipv6_connectivity()) {
        warnlog(logger, "IPv6 is NOT available, skipping this test");
        return;
    }

    using namespace std::chrono_literals;
    SocketFactory socket_factory({});
    UpstreamFactory upstream_factory({&socket_factory});
    const auto [upstream, err_upstream]
            = upstream_factory.create_upstream({.address = DNS64_SERVER_ADDR, .timeout = 5000ms});
    ASSERT_FALSE(err_upstream.has_value()) << err_upstream.value();

    const auto [prefs, err_prefs] = ag::dns64::discover_prefixes(upstream);
    ASSERT_FALSE(err_prefs.has_value()) << err_prefs.value();

    ASSERT_FALSE(prefs.empty()) << "No Pref64::/n found";

    const std::set<Uint8Vector> prefs_set(prefs.cbegin(), prefs.cend());
    ASSERT_EQ(prefs.size(), prefs_set.size()) << "Found prefixes are not unique";
}

static void check_synth(const Uint8View pref64, const Uint8View ip4, const Uint8Array<16> &expect_result) {
    auto [result, err] = ag::dns64::synthesize_ipv4_embedded_ipv6_address(pref64, ip4);
    ASSERT_FALSE(err.has_value()) << err.value();
    ASSERT_EQ(result, expect_result);
}

TEST(Dns64Test, TestIpv6Synthesis) {
    constexpr uint8_t ip4[] = {1, 2, 3, 4};
    const Uint8View ip4_v{ip4, std::size(ip4)};

    constexpr uint8_t pref[] = {5, 5, 5, 5, 5, 5, 5, 5, 0, 5, 5, 5};

    constexpr Uint8Array<16> expect_4 = {5, 5, 5, 5, 1, 2, 3, 4, 0}; // rest is zeroes
    constexpr Uint8Array<16> expect_5 = {5, 5, 5, 5, 5, 1, 2, 3, 0, 4}; // rest is zeroes
    constexpr Uint8Array<16> expect_6 = {5, 5, 5, 5, 5, 5, 1, 2, 0, 3, 4}; // rest is zeroes
    constexpr Uint8Array<16> expect_7 = {5, 5, 5, 5, 5, 5, 5, 1, 0, 2, 3, 4}; // rest is zeroes
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
    auto [result_10, err_10] = ag::dns64::synthesize_ipv4_embedded_ipv6_address({pref, 10}, ip4_v);
    ASSERT_TRUE(err_10.has_value());
}

} // namespace ag::dns64::test
