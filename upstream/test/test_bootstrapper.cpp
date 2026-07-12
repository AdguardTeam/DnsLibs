#include <chrono>
#include <gtest/gtest.h>

#include "common/clock.h"
#include "common/logger.h"
#include "dns/net/socket.h"
#include "dns/upstream/bootstrapper.h"

#include "dns_test_helpers.h"
#include "loopback_dns_server.h"

using namespace std::chrono;

namespace ag::dns::upstream::test {

struct BootstrapperTest : ::testing::Test {
protected:
    void SetUp() override {
        Logger::set_log_level(LogLevel::LOG_LEVEL_TRACE);
    }
};

TEST_F(BootstrapperTest, DontWaitAll) {
    // In-process loopback responder: replies with an A answer for any query so
    // the bootstrapper resolves "example.com" offline. The second bootstrap
    // (127.0.0.1:55) is a dead loopback port -> connection refused fast.
    ag::test::LoopbackDnsServer server([](const ldns_pkt &req) -> ldns_pkt_ptr {
        ldns_pkt_ptr reply = ag::test::make_base_reply(req);
        if (const ldns_rr *question = ldns_rr_list_rr(ldns_pkt_question(&req), 0); question != nullptr) {
            ag::test::add_a_answer(reply.get(), question);
        }
        return reply;
    });
    server.start();
    EventLoopPtr loop = EventLoop::create();
    loop->start();
    SocketFactory socket_factory({*loop});
    Bootstrapper::Params bootstrapper_params = {
            .address_string = "example.com",
            .default_port = 0,
            // The Resolver requires bare ip:port bootstrap addresses (no scheme),
            // so use the loopback server's plain address. 127.0.0.1:55 is a dead
            // loopback port -> connection refused fast.
            .bootstrap = {AG_FMT("127.0.0.1:{}", server.port()), "127.0.0.1:55"},
            .timeout = Secs(30),
            .upstream_config = {*loop, &socket_factory},
    };
    auto bootstrapper = std::make_unique<Bootstrapper>(bootstrapper_params);
    auto err = bootstrapper->init();
    ASSERT_FALSE(err) << err->str();

    auto before_ts = SteadyClock::now();
    Bootstrapper::ResolveResult result =
            coro::to_future([](EventLoop &loop, Bootstrapper &bootstrapper) -> coro::Task<Bootstrapper::ResolveResult> {
                co_await loop.co_submit();
                co_return co_await bootstrapper.get();
            }(*loop, *bootstrapper))
                    .get();
    bootstrapper.reset();
    loop->stop();
    loop->join();
    server.stop();
    auto after_ts = SteadyClock::now();

    ASSERT_FALSE(result.error) << result.error->str();
    ASSERT_FALSE(result.addresses.empty());
    ASSERT_LT(duration_cast<Millis>(after_ts - before_ts), bootstrapper_params.timeout / 2);
}

} // namespace ag::dns::upstream::test
