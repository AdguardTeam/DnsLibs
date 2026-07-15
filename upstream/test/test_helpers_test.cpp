// Unit tests for the shared test helpers in common/test_helpers/.
//
// NOTE: this file lives under upstream/test/ (not common/test/) on purpose.
// MockUpstream derives from dns::Upstream (which holds an ada::url_aggregator
// member, linking against the ada library) and the loopback round-trip tests
// exercise PlainUpstream / UpstreamFactory / SocketFactory from the upstream
// and net modules. The common module cannot link those (it is configured
// before upstream/net), so the test is co-located with its dependencies here.
// The headers themselves remain in common/test_helpers/ for reuse by every
// consuming test target.

#include <array>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <ldns/ldns.h>
#include <memory>
#include <string>

#include "common/gtest_coro.h"
#include "dns/common/event_loop.h"
#include "dns/net/socket.h"
#include "dns/upstream/upstream.h"

#include "dns_test_helpers.h"
#include "integration_test_guard.h"
#include "loopback_dns_server.h"
#include "mock_upstream.h"

namespace ag::dns::upstream::test {

namespace {
// A fixed query id so request/reply matching is deterministic.
constexpr uint16_t QUERY_ID = 0x4242;

void set_env_var(const char *name, const char *value) {
#ifdef _WIN32
    (void) ::_putenv_s(name, value);
#else
    (void) ::setenv(name, value, 1);
#endif
}

void unset_env_var(const char *name) {
#ifdef _WIN32
    (void) ::_putenv_s(name, "");
#else
    (void) ::unsetenv(name);
#endif
}

// Builds a DNS query for `name` with a fixed id.
ldns_pkt_ptr make_query(const char *name, ldns_rr_type type) {
    ldns_pkt *pkt = ldns_pkt_query_new(ldns_dname_new_frm_str(name), type, LDNS_RR_CLASS_IN, LDNS_RD);
    ldns_pkt_set_id(pkt, QUERY_ID);
    return ldns_pkt_ptr{pkt};
}

// Canned A-record (1.2.3.4) reply echoing the request's qname.
// Uses the shared test helpers from dns_test_helpers.h.
ldns_pkt_ptr make_canned_a_reply(const ldns_pkt &request) {
    ldns_pkt_ptr reply = ag::test::make_base_reply(request);
    const ldns_rr *question = ldns_rr_list_rr(ldns_pkt_question(&request), 0);
    if (question == nullptr) {
        return {};
    }
    ag::test::add_a_answer(reply.get(), question);
    return reply;
}

// Returns an empty string if `reply` is the expected canned A (1.2.3.4)
// response, otherwise a human-readable description of the mismatch. Kept
// ASSERT-free so it can be called from a helper (ASSERT_* expands to a
// coroutine co_return under gtest_coro, which is only valid in a test body).
std::string check_canned_a_reply(const ldns_pkt &reply) {
    if (ldns_pkt_get_rcode(&reply) != LDNS_RCODE_NOERROR) {
        return "expected NOERROR rcode";
    }
    if (ldns_pkt_ancount(&reply) != 1u) {
        return "expected exactly one answer";
    }
    const ldns_rr *answer = ldns_rr_list_rr(ldns_pkt_answer(&reply), 0);
    if (answer == nullptr) {
        return "answer section is empty";
    }
    if (ldns_rr_get_type(answer) != LDNS_RR_TYPE_A) {
        return "expected an A answer";
    }
    const ldns_rdf *rdf = ldns_rr_rdf(answer, 0);
    if (rdf == nullptr) {
        return "answer has no rdata";
    }
    constexpr std::array<uint8_t, 4> expected{1, 2, 3, 4};
    if (ldns_rdf_size(rdf) != expected.size()
            || std::memcmp(ldns_rdf_data(rdf), expected.data(), expected.size()) != 0) {
        return "answer data is not 1.2.3.4";
    }
    return {};
}
} // namespace

class TestHelpersTest : public ::testing::Test {
protected:
    void SetUp() override {
        m_loop = EventLoop::create();
        m_loop->start();
        SocketFactory::Parameters params{.loop = *m_loop};
        m_socket_factory = std::make_unique<SocketFactory>(std::move(params));
    }

    void TearDown() override {
        m_socket_factory.reset();
        m_loop->stop();
        m_loop->join();
    }

    EventLoopPtr m_loop;
    std::unique_ptr<SocketFactory> m_socket_factory;
};

TEST_F(TestHelpersTest, IntegrationGuardReflectsEnvVar) {
    unset_env_var("DNSLIBS_INTEGRATION_TESTS");
    EXPECT_FALSE(ag::test::integration_tests_enabled());
    set_env_var("DNSLIBS_INTEGRATION_TESTS", "1");
    EXPECT_TRUE(ag::test::integration_tests_enabled());
    // Any value other than "1" (including "0") must be treated as disabled, so
    // the variable cannot be set to disable real-network tests by accident.
    set_env_var("DNSLIBS_INTEGRATION_TESTS", "0");
    EXPECT_FALSE(ag::test::integration_tests_enabled());
    set_env_var("DNSLIBS_INTEGRATION_TESTS", "false");
    EXPECT_FALSE(ag::test::integration_tests_enabled());
    unset_env_var("DNSLIBS_INTEGRATION_TESTS");
    co_return;
}

TEST_F(TestHelpersTest, MockUpstreamReturnsCannedResponse) {
    co_await m_loop->co_submit();
    auto mock = std::make_shared<ag::test::MockUpstream>(UpstreamOptions{.address = "mock://upstream"},
            UpstreamFactoryConfig{.loop = *m_loop, .socket_factory = m_socket_factory.get(), .timeout = Millis{1000}});
    auto init_err = mock->init();
    ASSERT_EQ(init_err, nullptr);
    ldns_pkt_ptr req = make_query("example.com.", LDNS_RR_TYPE_A);
    auto res = co_await mock->exchange(req.get());
    ASSERT_FALSE(res.has_error()) << res.error()->str();
    std::string err = check_canned_a_reply(*res.value());
    ASSERT_TRUE(err.empty()) << err;
}

TEST_F(TestHelpersTest, MockUpstreamInvokesHandler) {
    co_await m_loop->co_submit();
    auto mock = std::make_shared<ag::test::MockUpstream>(UpstreamOptions{.address = "mock://upstream"},
            UpstreamFactoryConfig{.loop = *m_loop, .socket_factory = m_socket_factory.get(), .timeout = Millis{1000}});
    mock->m_handler = [](const ldns_pkt *, const DnsMessageInfo *) {
        return ag::test::MockUpstream::make_dns_error(DnsError::AE_SOCKET_ERROR, "injected");
    };
    auto init_err = mock->init();
    ASSERT_EQ(init_err, nullptr);
    ldns_pkt_ptr req = make_query("example.com.", LDNS_RR_TYPE_A);
    auto res = co_await mock->exchange(req.get());
    ASSERT_TRUE(res.has_error());
    ASSERT_EQ(res.error()->value(), DnsError::AE_SOCKET_ERROR);
}

TEST_F(TestHelpersTest, LoopbackServerRepliesOverUdp) {
    co_await m_loop->co_submit();
    ag::test::LoopbackDnsServer server([](const ldns_pkt &request) {
        return make_canned_a_reply(request);
    });
    server.start();
    UpstreamFactory factory({.loop = *m_loop, .socket_factory = m_socket_factory.get(), .timeout = Millis{1000}});
    auto upstream_res = factory.create_upstream({.address = server.address(ag::utils::TP_UDP)});
    ASSERT_FALSE(upstream_res.has_error()) << upstream_res.error()->str();
    ldns_pkt_ptr req = make_query("example.com.", LDNS_RR_TYPE_A);
    auto reply_res = co_await upstream_res.value()->exchange(req.get());
    ASSERT_FALSE(reply_res.has_error()) << reply_res.error()->str();
    std::string err = check_canned_a_reply(*reply_res.value());
    ASSERT_TRUE(err.empty()) << err;
    server.stop();
}

TEST_F(TestHelpersTest, LoopbackServerRepliesOverTcp) {
    co_await m_loop->co_submit();
    ag::test::LoopbackDnsServer server([](const ldns_pkt &request) {
        return make_canned_a_reply(request);
    });
    server.start();
    UpstreamFactory factory({.loop = *m_loop, .socket_factory = m_socket_factory.get(), .timeout = Millis{1000}});
    auto upstream_res = factory.create_upstream({.address = server.address(ag::utils::TP_TCP)});
    ASSERT_FALSE(upstream_res.has_error()) << upstream_res.error()->str();
    ldns_pkt_ptr req = make_query("example.com.", LDNS_RR_TYPE_A);
    auto reply_res = co_await upstream_res.value()->exchange(req.get());
    ASSERT_FALSE(reply_res.has_error()) << reply_res.error()->str();
    std::string err = check_canned_a_reply(*reply_res.value());
    ASSERT_TRUE(err.empty()) << err;
    server.stop();
}

TEST_F(TestHelpersTest, LoopbackServerDropsReturnNoReply) {
    co_await m_loop->co_submit();
    ag::test::LoopbackDnsServer server([](const ldns_pkt &) {
        return ldns_pkt_ptr{};
    });
    server.start();
    UpstreamFactory factory({.loop = *m_loop, .socket_factory = m_socket_factory.get(), .timeout = Millis{200}});
    auto upstream_res = factory.create_upstream({.address = server.address(ag::utils::TP_UDP)});
    ASSERT_FALSE(upstream_res.has_error()) << upstream_res.error()->str();
    ldns_pkt_ptr req = make_query("example.com.", LDNS_RR_TYPE_A);
    auto reply_res = co_await upstream_res.value()->exchange(req.get());
    ASSERT_TRUE(reply_res.has_error());
    server.stop();
}

} // namespace ag::dns::upstream::test
