#include <cerrno>
#include <chrono>
#include <gtest/gtest.h>

#ifdef __APPLE__
#include <sys/socket.h>
#endif // __APPLE__

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

#ifdef __APPLE__
TEST_F(BootstrapperTest, LocalNetworkPermissionMaybeMissing) {
    EventLoopPtr loop = EventLoop::create();
    loop->start();
    SocketFactory socket_factory({
            .loop = *loop,
            // On Apple platforms a connected UDP socket reports EPIPE when the application is missing
            // the Local Network permission. Emulate it by shutting down the write side of every socket.
            .protect_fd = [](evutil_socket_t fd, const SocketAddress &peer) -> Error<SocketError> {
                if (::connect(fd, peer.c_sockaddr(), peer.c_socklen()) != 0 || ::shutdown(fd, SHUT_WR) != 0) {
                    return make_error(SocketError::AE_SOCK_ERROR, AG_FMT("Failed to set up test socket: {}", errno));
                }
                return {};
            },
    });
    Bootstrapper::Params bootstrapper_params = {
            .address_string = "example.com",
            .default_port = 0,
            // The failure of the loopback resolver is unrelated to the Local Network permission,
            // and must not hide the possibly missing permission reported for the private network resolver.
            .bootstrap = {"192.168.1.1:53", "127.0.0.1:55"},
            .timeout = Secs(30),
            .upstream_config = {*loop, &socket_factory},
    };
    auto bootstrapper = std::make_unique<Bootstrapper>(bootstrapper_params);
    auto err = bootstrapper->init();
    ASSERT_FALSE(err) << err->str();

    Bootstrapper::ResolveResult result =
            coro::to_future([](EventLoop &loop, Bootstrapper &bootstrapper) -> coro::Task<Bootstrapper::ResolveResult> {
                co_await loop.co_submit();
                co_return co_await bootstrapper.get();
            }(*loop, *bootstrapper))
                    .get();
    bootstrapper.reset();
    loop->stop();
    loop->join();

    ASSERT_TRUE(result.error);
    ASSERT_EQ(result.error->value(), Bootstrapper::BootstrapperError::AE_LOCAL_NETWORK_PERMISSION_MAYBE_MISSING)
            << result.error->str();
    Error<DnsError> exchange_error = make_bootstrap_error(result.error);
    ASSERT_EQ(exchange_error->value(), DnsError::AE_BOOTSTRAP_LOCAL_NETWORK_PERMISSION_MAYBE_MISSING)
            << exchange_error->str();
}
#endif // __APPLE__

} // namespace ag::dns::upstream::test
