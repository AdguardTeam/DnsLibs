#include <chrono>
#include <gtest/gtest.h>
#include <ag_logger.h>
#include <ag_socket.h>
#include <bootstrapper.h>


using namespace std::chrono;


struct BootstrapperTest : ::testing::Test {
protected:
    void SetUp() override {
        ag::set_default_log_level(ag::TRACE);
    }
};


TEST_F(BootstrapperTest, DontWaitAll) {
    ag::socket_factory socket_factory({});
    ag::bootstrapper::params bootstrapper_params = {
            .address_string = "example.com",
            .default_port = 0,
            .bootstrap = { "1.1.1.1:53", "1.1.1.1:55" },
            .timeout = seconds(30),
            .upstream_config = { &socket_factory },
    };
    ag::bootstrapper bootstrapper(bootstrapper_params);
    ag::err_string err = bootstrapper.init();
    ASSERT_FALSE(err.has_value()) << err.value();

    auto before_ts = steady_clock::now();
    ag::bootstrapper::resolve_result result = bootstrapper.get();
    auto after_ts = steady_clock::now();

    ASSERT_FALSE(result.error.has_value()) << result.error.value();
    ASSERT_FALSE(result.addresses.empty());
    ASSERT_LT(duration_cast<milliseconds>(after_ts - before_ts), bootstrapper_params.timeout / 2);
}
