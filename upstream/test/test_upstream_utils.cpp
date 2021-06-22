#include "gtest/gtest.h"
#include "upstream_utils.h"
#include <magic_enum.hpp>

struct upstream_utils_test : ::testing::Test {};

TEST_F(upstream_utils_test, test_upstream) {
    using namespace std::chrono_literals;

    static constexpr auto timeout = 500ms;
    auto err = ag::test_upstream({"123.12.32.1:1493", {}, timeout}, false, nullptr);
    ASSERT_TRUE(err) << "Cannot be successful";

    err = ag::test_upstream({"8.8.8.8:53", {}, 10 * timeout}, false, nullptr);
    ASSERT_FALSE(err) << "Cannot fail: " << *err;

    // Test for DoT with 2 bootstraps. Only one is valid
    // Use stub verifier b/c certificate verification is not part of the tested logic
    // and would fail on platforms where it is unsupported by ag::default_verifier
    err = ag::test_upstream({"tls://dns.adguard.com", {"1.2.3.4", "8.8.8.8"}, 10 * timeout}, false,
                            [](const ag::certificate_verification_event &) { return std::nullopt; });
    ASSERT_FALSE(err) << "Cannot fail: " << *err;
}
