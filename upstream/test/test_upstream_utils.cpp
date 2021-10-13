#include "gtest/gtest.h"
#include "upstream_utils.h"
#include <magic_enum.hpp>


using namespace std::chrono_literals;


static constexpr auto timeout = 500ms;


struct upstream_utils_test : ::testing::Test {
protected:
    void SetUp() override {
        ag::set_default_log_level(ag::TRACE);
    }
};

TEST_F(upstream_utils_test, invalid_upstream_online) {
    auto err = ag::test_upstream({"123.12.32.1:1493", {}, timeout}, false, nullptr, false);
    ASSERT_TRUE(err) << "Cannot be successful";
}

TEST_F(upstream_utils_test, valid_upstream_online) {
    auto err = ag::test_upstream({"8.8.8.8:53", {}, 10 * timeout}, false, nullptr, false);
    ASSERT_FALSE(err) << "Cannot fail: " << *err;

    // Test for DoT with 2 bootstraps. Only one is valid
    // Use stub verifier b/c certificate verification is not part of the tested logic
    // and would fail on platforms where it is unsupported by ag::default_verifier
    err = ag::test_upstream({"tls://dns.adguard.com", {"1.2.3.4", "8.8.8.8"}, 10 * timeout}, false,
            [](const ag::certificate_verification_event &) { return std::nullopt; },
            false);
    ASSERT_FALSE(err) << "Cannot fail: " << *err;
}

TEST_F(upstream_utils_test, invalid_upstream_offline_looks_valid) {
    auto err = ag::test_upstream({"123.12.32.1:1493", {}, timeout}, false, nullptr, true);
    ASSERT_FALSE(err) << "Cannot fail: " << *err;
}

TEST_F(upstream_utils_test, invalid_upstream_offline_unknown_scheme) {
    auto err = ag::test_upstream({"unk://123.12.32.1:1493", {}, timeout}, false, nullptr, true);
    ASSERT_TRUE(err) << "Cannot be successful";
}
