#include <chrono>
#include <gtest/gtest.h>

#include "common/clock.h"
#include "common/logger.h"
#include "dns/net/socket.h"
#include "dns/upstream/bootstrapper.h"

using namespace std::chrono;

namespace ag::dns::upstream::test {

struct BootstrapperTest : ::testing::Test {
protected:
    void SetUp() override {
        Logger::set_log_level(LogLevel::LOG_LEVEL_TRACE);
    }
};

TEST_F(BootstrapperTest, DontWaitAll) {
    EventLoopPtr loop = EventLoop::create();
    loop->start();
    SocketFactory socket_factory({*loop});
    Bootstrapper::Params bootstrapper_params = {
            .address_string = "example.com",
            .default_port = 0,
            .bootstrap = {"1.1.1.1:53", "1.1.1.1:55"},
            .timeout = Secs(30),
            .upstream_config = {*loop, &socket_factory},
    };
    auto bootstrapper = std::make_unique<Bootstrapper>(bootstrapper_params);
    auto err = bootstrapper->init();
    ASSERT_FALSE(err) << err->str();

    auto before_ts = SteadyClock::now();
    Bootstrapper::ResolveResult result = coro::to_future(
            [](EventLoop &loop, Bootstrapper &bootstrapper) -> coro::Task<Bootstrapper::ResolveResult> {
                co_await loop.co_submit();
                co_return co_await bootstrapper.get();
            }(*loop, *bootstrapper)).get();
    bootstrapper.reset();
    loop->stop();
    loop->join();
    auto after_ts = SteadyClock::now();

    ASSERT_FALSE(result.error) << result.error->str();
    ASSERT_FALSE(result.addresses.empty());
    ASSERT_LT(duration_cast<Millis>(after_ts - before_ts), bootstrapper_params.timeout / 2);
}

} // namespace ag::dns::upstream::test
