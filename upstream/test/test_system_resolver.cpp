#include <csignal>
#include <functional>
#include <future>
#include <net/if.h>
#include <optional>
#include <thread>

#include <dns_sd.h>
#include <fmt/chrono.h>
#include <ldns/ldns.h>

#include "../system_resolver.h"
#include "common/gtest_coro.h"
#include "integration_test_guard.h"

namespace ag::dns::upstream::test {

class SystemResolverTest : public ::testing::Test {
protected:
    std::unique_ptr<SystemResolver> m_resolver;
    EventLoopPtr m_loop;

    void SetUp() override {
        Logger::set_log_level(LOG_LEVEL_TRACE);
        m_loop = EventLoop::create();
        m_loop->start();
        m_resolver = std::move(SystemResolver::create(m_loop.get(), Secs{5}, 0).value());
    }
    void TearDown() override {
        m_resolver.reset();
        m_loop->stop();
        m_loop->join();
        m_loop.reset();
    }
};

TEST_F(SystemResolverTest, ResolveMicrosoftARecord) {
    // www.microsoft.com is served via a CDN, so its resolution follows a CNAME
    // chain (e.g. www.microsoft.com -> *.edgekey.net -> *.akamaiedge.net -> A)
    // before reaching the final A record. This verifies two things: that the
    // SystemResolver works end-to-end against the real OS system resolver, and
    // that it surfaces the final A record(s) from a domain whose resolution
    // involves CNAME records. The exact record count (and the number of A
    // records) varies by CDN edge / region, so we only assert that at least one
    // A record is returned rather than a fixed count. Uses the OS system
    // resolver, which depends on the real network.
    REQUIRE_INTEGRATION();
    co_await m_loop->co_submit();
    auto result = co_await m_resolver->resolve("www.microsoft.com", LDNS_RR_TYPE_A);
    ASSERT_FALSE(result.has_error());
    const auto &rr_list = result.value();
    ASSERT_NE(rr_list, nullptr);
    size_t a_count = 0;
    for (size_t i = 0; i < ldns_rr_list_rr_count(rr_list.get()); ++i) {
        if (ldns_rr_get_type(ldns_rr_list_rr(rr_list.get(), i)) == LDNS_RR_TYPE_A) {
            ++a_count;
        }
    }
    ASSERT_GE(a_count, 1) << "Expected at least one A record in the resolution";
}

TEST_F(SystemResolverTest, ResolveNonExistentDomain) {
    // Uses the OS system resolver, which depends on the real network.
    REQUIRE_INTEGRATION();
    co_await m_loop->co_submit();
    const auto RESULT = co_await m_resolver->resolve("nonexistentdomainabcdefgh.xyz", LDNS_RR_TYPE_A);
    ASSERT_TRUE(RESULT.has_error());
    ASSERT_TRUE(RESULT.error()->value() == SystemResolverError::AE_DOMAIN_NOT_FOUND
            || RESULT.error()->value() == SystemResolverError::AE_RECORD_NOT_FOUND
            || RESULT.error()->value() == SystemResolverError::AE_SYSTEM_RESOLVE_ERROR);
}

TEST_F(SystemResolverTest, ResolveNoWait) {
    // Uses the OS system resolver, which depends on the real network.
    REQUIRE_INTEGRATION();
    co_await m_loop->co_submit();
    coro::run_detached([](SystemResolver *resolver) -> coro::Task<void> {
        co_await resolver->resolve("www.example.org", LDNS_RR_TYPE_A);
    }(m_resolver.get()));
    m_resolver.reset();
    co_return;
}

// The observations of `resolve_and_retry()`.
struct ResolveRetryState {
    bool destroying = false;      ///< Set by the test before the resolver is destroyed.
    bool first_completed = false; ///< Whether the first query completed before the destruction started.
    bool retried_during_destruction = false;
    std::optional<Result<SystemResolver::LdnsRrListPtr, SystemResolverError>> retry_result;
};

// Issues a resolve and, once it completes, immediately issues another one. If the first resolve is
// completed by the resolver destructor, the retry is sent while the resolver is being destroyed.
static coro::Task<void> resolve_and_retry(SystemResolver *resolver, ResolveRetryState &state) {
    (void) co_await resolver->resolve("www.example.org", LDNS_RR_TYPE_A);
    state.first_completed = true;
    state.retried_during_destruction = state.destroying;
    state.retry_result = co_await resolver->resolve("www.example.org", LDNS_RR_TYPE_A);
}

// A coroutine resumed by the destructor may immediately resolve another name (e.g. a caller that
// retries on `AE_SHUTTING_DOWN`). Such requests must be rejected instead of modifying the request
// map while it's being drained.
TEST_F(SystemResolverTest, RejectsRequestsSentWhileDestroying) {
    // Uses the OS system resolver, which depends on the real network.
    REQUIRE_INTEGRATION();
    co_await m_loop->co_submit();
    ResolveRetryState state;
    std::future<void> completion = coro::to_future(resolve_and_retry(m_resolver.get(), state));
    // If the first resolve completed synchronously, the retry was sent before the destruction started.
    if (state.first_completed) {
        GTEST_SKIP() << "The first query has completed synchronously";
    }

    state.destroying = true;
    m_resolver.reset();

    ASSERT_EQ(std::future_status::ready, completion.wait_for(std::chrono::seconds{0}));
    ASSERT_TRUE(state.retried_during_destruction);
    ASSERT_TRUE(state.retry_result.has_value());
    ASSERT_TRUE(state.retry_result->has_error());
    // The error is produced by `resolve()`'s guard, not by the destructor completing a request that
    // was accepted: an accepted retry would carry the destructor's message-less error.
    ASSERT_EQ(SystemResolverError::AE_SHUTTING_DOWN, state.retry_result->error()->value())
            << state.retry_result->error()->str();
    ASSERT_NE(std::string::npos, state.retry_result->error()->str().find("being destroyed"))
            << state.retry_result->error()->str();
}

} // namespace ag::dns::upstream::test
