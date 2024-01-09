#include <csignal>
#include <functional>
#include <future>
#include <net/if.h>
#include <thread>

#include <dns_sd.h>
#include <fmt/chrono.h>
#include <ldns/ldns.h>

#include "../system_resolver.h"
#include "common/gtest_coro.h"

namespace ag::dns::upstream::test {

class SystemResolverTest : public ::testing::Test {
protected:
    std::unique_ptr<SystemResolver> m_resolver;
    EventLoopPtr m_loop;

    void SetUp() override {
        m_loop = EventLoop::create();
        m_loop->start();
        m_resolver = std::move(SystemResolver::create(m_loop.get(), 0).value());
    }
    void TearDown() override {
        m_resolver.reset();
        m_loop->stop();
        m_loop->join();
        m_loop.reset();
    }
};

TEST_F(SystemResolverTest, ResolveGoogleARecord) {
    auto result = co_await m_resolver->resolve("www.microsoft.com", LDNS_RR_TYPE_A);
    ASSERT_FALSE(result.has_error());
    const auto &rr_list = result.value();
    ASSERT_NE(rr_list, nullptr);
    ASSERT_EQ(ldns_rr_list_rr_count(rr_list.get()), 4);
}

TEST_F(SystemResolverTest, ResolveNonExistentDomain) {
    const auto RESULT = co_await m_resolver->resolve("nonexistentdomainabcdefgh.xyz", LDNS_RR_TYPE_A);
    ASSERT_TRUE(RESULT.has_error());
    ASSERT_TRUE(RESULT.error()->value() == SystemResolverError::AE_DOMAIN_NOT_FOUND
            || RESULT.error()->value() == SystemResolverError::AE_SYSTEM_RESOLVE_ERROR);
}

} // namespace ag::dns::upstream::test