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
        Logger::set_log_level(LOG_LEVEL_TRACE);
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

TEST_F(SystemResolverTest, ResolveMicrosoftARecord) {
    co_await m_loop->co_submit();
    auto result = co_await m_resolver->resolve("www.microsoft.com", LDNS_RR_TYPE_A);
    ASSERT_FALSE(result.has_error());
    const auto &rr_list = result.value();
    ASSERT_NE(rr_list, nullptr);
    ASSERT_EQ(ldns_rr_list_rr_count(rr_list.get()), 4);
}

TEST_F(SystemResolverTest, ResolveNonExistentDomain) {
    co_await m_loop->co_submit();
    const auto RESULT = co_await m_resolver->resolve("nonexistentdomainabcdefgh.xyz", LDNS_RR_TYPE_A);
    ASSERT_TRUE(RESULT.has_error());
    ASSERT_TRUE(RESULT.error()->value() == SystemResolverError::AE_DOMAIN_NOT_FOUND
            || RESULT.error()->value() == SystemResolverError::AE_RECORD_NOT_FOUND
            || RESULT.error()->value() == SystemResolverError::AE_SYSTEM_RESOLVE_ERROR);
}

TEST_F(SystemResolverTest, ResolveNoWait) {
    co_await m_loop->co_submit();
    coro::run_detached([](SystemResolver *resolver) -> coro::Task<void> {
        co_await resolver->resolve("www.example.org", LDNS_RR_TYPE_A);
    }(m_resolver.get()));
    m_resolver.reset();
    co_return;
}

} // namespace ag::dns::upstream::test
