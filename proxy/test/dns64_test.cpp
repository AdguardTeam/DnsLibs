#include <gtest/gtest.h>
#include <dns64.h>
#include <upstream_utils.h>
#include <ag_logger.h>

static constexpr auto DNS64_SERVER_ADDR = "2001:4860:4860::6464";

TEST(dns64_test, test_dns64_discovery) {
    if (!ag::test_ipv6_connectivity()) {
        SPDLOG_WARN("IPv6 is NOT available, skipping this test");
        return;
    }

    using namespace std::chrono_literals;
    ag::upstream_factory upstream_factory({});
    const auto[upstream, err_upstream] = upstream_factory.create_upstream({
            .address = DNS64_SERVER_ADDR,
            .timeout = 5000ms
        });
    ASSERT_FALSE(err_upstream.has_value()) << err_upstream.value();

    const auto[prefs, err_prefs] = ag::dns64::discover_prefixes(upstream);
    ASSERT_FALSE(err_prefs.has_value()) << err_prefs.value();

    ASSERT_FALSE(prefs.empty()) << "No Pref64::/n found";

    const std::set<ag::uint8_vector> prefs_set(prefs.cbegin(), prefs.cend());
    ASSERT_EQ(prefs.size(), prefs_set.size()) << "Found prefixes are not unique";
}

static void check_synth(const ag::uint8_view pref64,
                        const ag::uint8_view ip4,
                        const ag::uint8_array<16> &expect_result) {
    auto[result, err] = ag::dns64::synthesize_ipv4_embedded_ipv6_address(pref64, ip4);
    ASSERT_FALSE(err.has_value()) << err.value();
    ASSERT_EQ(result, expect_result);
}

TEST(dns64_test, test_ipv6_synthesis) {
    constexpr uint8_t ip4[] = {1, 2, 3, 4};
    const ag::uint8_view ip4_v{ip4, std::size(ip4)};

    constexpr uint8_t pref[] = {5, 5, 5, 5, 5, 5, 5, 5, 0, 5, 5, 5};

    constexpr ag::uint8_array<16> expect_4 = {5, 5, 5, 5, 1, 2, 3, 4, 0}; // rest is zeroes
    constexpr ag::uint8_array<16> expect_5 = {5, 5, 5, 5, 5, 1, 2, 3, 0, 4}; // rest is zeroes
    constexpr ag::uint8_array<16> expect_6 = {5, 5, 5, 5, 5, 5, 1, 2, 0, 3, 4}; // rest is zeroes
    constexpr ag::uint8_array<16> expect_7 = {5, 5, 5, 5, 5, 5, 5, 1, 0, 2, 3, 4}; // rest is zeroes
    constexpr ag::uint8_array<16> expect_8 = {5, 5, 5, 5, 5, 5, 5, 5, 0, 1, 2, 3, 4}; // rest is zeroes
    constexpr ag::uint8_array<16> expect_12 = {5, 5, 5, 5, 5, 5, 5, 5, 0, 5, 5, 5, 1, 2, 3, 4};

    // Check allowed pref lengths
    check_synth({pref, 4}, ip4_v, expect_4);
    check_synth({pref, 5}, ip4_v, expect_5);
    check_synth({pref, 6}, ip4_v, expect_6);
    check_synth({pref, 7}, ip4_v, expect_7);
    check_synth({pref, 8}, ip4_v, expect_8);
    check_synth({pref, 12}, ip4_v, expect_12);

    // Check disallowed pref length...
    auto[result_10, err_10] = ag::dns64::synthesize_ipv4_embedded_ipv6_address({pref, 10}, ip4_v);
    ASSERT_TRUE(err_10.has_value());
}
