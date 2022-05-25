#include <chrono>
#include <gtest/gtest.h>

#include "common/clock.h"
#include "common/logger.h"
#include "net/socket.h"

#include "../bootstrapper.h"

using namespace std::chrono;

namespace ag::upstream::test {

struct BootstrapperTest : ::testing::Test {
protected:
    void SetUp() override {
        Logger::set_log_level(LogLevel::LOG_LEVEL_TRACE);
    }
};

TEST_F(BootstrapperTest, DontWaitAll) {
    SocketFactory socket_factory({});
    Bootstrapper::Params bootstrapper_params = {
            .address_string = "example.com",
            .default_port = 0,
            .bootstrap = {"1.1.1.1:53", "1.1.1.1:55"},
            .timeout = Secs(30),
            .upstream_config = {&socket_factory},
    };
    Bootstrapper bootstrapper(bootstrapper_params);
    ErrString err = bootstrapper.init();
    ASSERT_FALSE(err.has_value()) << err.value();

    auto before_ts = SteadyClock::now();
    Bootstrapper::ResolveResult result = bootstrapper.get();
    auto after_ts = SteadyClock::now();

    ASSERT_FALSE(result.error.has_value()) << result.error.value();
    ASSERT_FALSE(result.addresses.empty());
    ASSERT_LT(duration_cast<Millis>(after_ts - before_ts), bootstrapper_params.timeout / 2);
}

} // namespace ag::upstream::test
