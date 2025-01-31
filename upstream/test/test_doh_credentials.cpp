#include <gtest/gtest.h>
#include <memory>
#include <string>

#include "common/gtest_coro.h"
#include "common/base64.h"
#include "common/utils.h"
#include "dns/common/event_loop.h"
#include "dns/net/socket.h"
#include "dns/upstream/upstream.h"

#include "../upstream_doh.h"

namespace ag::dns::upstream::test {

struct DohCredentialTestParam {
    std::string url;
    std::string expected_username;
    std::string expected_password;
};

class DohUpstreamParamTest : public ::testing::TestWithParam<DohCredentialTestParam> {
public:
    void SetUp() override {
        m_loop = EventLoop::create();
        m_loop->start();
    }

    void TearDown() override {
        m_loop->stop();
        m_loop->join();
    }

    EventLoopPtr m_loop;
};

TEST_P(DohUpstreamParamTest, ParsesCredentialsCorrectly) {
    co_await m_loop->co_submit();

    const auto &param = GetParam();

    SocketFactory sf{{.loop = *m_loop}};
    UpstreamFactory factory({.loop = *m_loop, .socket_factory = &sf});

    UpstreamOptions options;
    options.address = param.url;
    options.bootstrap = {"8.8.8.8"};

    auto upstream_res = factory.create_upstream(options);
    ASSERT_FALSE(upstream_res.has_error()) << "Failed to create Upstream for " << param.url;

    auto doh_upstream = std::dynamic_pointer_cast<DohUpstream>(upstream_res.value());
    ASSERT_NE(doh_upstream, nullptr) << "Failed to cast to DohUpstream";

    ASSERT_TRUE(doh_upstream->get_request_template().headers().get("Authorization").has_value());
    std::string test_header(doh_upstream->get_request_template().headers().get("Authorization").value());
    auto creds_expected = AG_FMT("{}:{}", param.expected_username, param.expected_password);
    auto creds_expected_base64 = ag::encode_to_base64(as_u8v(creds_expected), false);
    EXPECT_EQ(test_header, AG_FMT("Basic {}", creds_expected_base64));
}

static const DohCredentialTestParam doh_credential_test_cases[] = {
        {"https://username:password@dns.google/dns-query", "username", "password"},
        {"https://user%20name:password@dns.google/dns-query", "user name", "password"},
        {"https://username:pass%7Eword@dns.google/dns-query", "username", "pass~word"},
        {"https://user%7Cname:pass~word@dns.google/dns-query", "user|name", "pass~word"},
        {"https://username:pass%word@dns.google/dns-query", "username", "pass%word"},
        {"https://username:%7E%%7Cpassword@dns.google/dns-query", "username", "~%|password"},
        {"https://username:%00password@dns.google/dns-query", "username", std::string("\0password", 9)},
};

INSTANTIATE_TEST_SUITE_P(DohUpstreamParamTest, DohUpstreamParamTest,
        ::testing::ValuesIn(doh_credential_test_cases));

} // namespace ag::dns::upstream::test
