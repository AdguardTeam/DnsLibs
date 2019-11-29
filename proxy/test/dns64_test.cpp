#include <gtest/gtest.h>
#include <dns64.h>

static constexpr auto DNS64_SERVER_ADDR = "2001:67c:27e4::64";

TEST(dns64_test, test_dns64_discovery) {
    using namespace std::chrono_literals;
    const auto[upstream, err_upstream] = ag::upstream::address_to_upstream(
            DNS64_SERVER_ADDR,
            ag::upstream::options{
                    .timeout = 5000ms
            });
    ASSERT_FALSE(err_upstream.has_value()) << err_upstream.value();

    const auto[prefs, err_prefs] = ag::discover_dns64_prefixes(upstream);
    ASSERT_FALSE(err_prefs.has_value()) << err_prefs.value();

    ASSERT_FALSE(prefs.empty()) << "No Pref64::/n found";

    const std::set<ag::uint8_vector> prefs_set(prefs.cbegin(), prefs.cend());
    ASSERT_EQ(prefs.size(), prefs_set.size()) << "Found prefixes are not unique";
}

static void check_synth(const ag::uint8_view pref64,
                        const ag::uint8_view ip4,
                        const ag::uint8_array<16> &expect_result) {
    auto[result, err] = ag::synthesize_ipv4_embedded_ipv6_address(pref64, ip4);
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
    auto[result_10, err_10] = ag::synthesize_ipv4_embedded_ipv6_address({pref, 10}, ip4_v);
    ASSERT_TRUE(err_10.has_value());
}
