#include "dns/upstream/upstream_utils.h"
#include "gtest/gtest.h"
#include <magic_enum.hpp>

using namespace std::chrono_literals;

static constexpr auto timeout = 500ms;

namespace ag::dns::upstream::test {

struct UpstreamUtilsTest : ::testing::Test {
protected:
    void SetUp() override {
        Logger::set_log_level(LogLevel::LOG_LEVEL_TRACE);
    }
};

TEST_F(UpstreamUtilsTest, InvalidUpstreamOnline) {
    auto err = dns::test_upstream({"123.12.32.1:1493", {}}, timeout, false, nullptr, false);
    ASSERT_TRUE(err) << "Cannot be successful";
}

TEST_F(UpstreamUtilsTest, ValidUpstreamOnline) {
    auto err = dns::test_upstream({"8.8.8.8:53", {}}, 10 * timeout, false, nullptr, false);
    ASSERT_FALSE(err) << "Cannot fail: " << err->str();

    // Test for DoT with 2 bootstraps. Only one is valid
    // Use stub verifier b/c certificate verification is not part of the tested logic
    // and would fail on platforms where it is unsupported by ag::default_verifier
    err = dns::test_upstream(
            {"tls://1.1.1.1", {"1.2.3.4", "8.8.8.8"}}, 10 * timeout, false,
            [](const CertificateVerificationEvent &) {
                return std::nullopt;
            },
            false);
    ASSERT_FALSE(err) << "Cannot fail: " << err->str();
}

TEST_F(UpstreamUtilsTest, InvalidUpstreamOfflineLooksValid) {
    auto err = dns::test_upstream({"123.12.32.1:1493", {}}, timeout, false, nullptr, true);
    ASSERT_FALSE(err) << "Cannot fail: " << err->str();
}

TEST_F(UpstreamUtilsTest, InvalidUpstreamOfflineUnknownScheme) {
    auto err = dns::test_upstream({"unk://123.12.32.1:1493", {}}, timeout, false, nullptr, true);
    ASSERT_TRUE(err) << "Cannot be successful";
}

} // namespace ag::dns::upstream::test
