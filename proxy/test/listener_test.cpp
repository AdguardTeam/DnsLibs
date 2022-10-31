#include <atomic>
#include <condition_variable>
#include <gtest/gtest.h>
#include <ldns/ldns.h>
#include <magic_enum.hpp>
#include <thread>

#include "dns/proxy/dnsproxy.h"
#include "dns/upstream/upstream.h"

namespace ag::dns::proxy::test {

using namespace std::chrono_literals;

struct TestParams {
    ListenerSettings settings;
    size_t n_threads{1};
    size_t requests_per_thread{1};
    const char *request_addr{"::1"};
    const char *query{"google.com"};
};

class ListenerTest : public ::testing::TestWithParam<TestParams> {
protected:
    Logger log{"listener_test"};
};

TEST_P(ListenerTest, ListensAndResponds) {
    Logger::set_log_level(LogLevel::LOG_LEVEL_TRACE);

    std::mutex mtx;
    std::condition_variable proxy_cond;
    std::atomic_bool proxy_initialized{false};
    std::atomic_bool proxy_init_result{false};

    const auto params = GetParam();
    const auto listener_settings = params.settings;

    std::thread t([&]() {
        auto settings = DnsProxySettings::get_default();
        settings.upstreams = {{"94.140.14.140"}};
        settings.listeners = {listener_settings};

        // Since we do an AAAA query, this will prevent the proxy
        // from querying its upstream while still allowing to test the listener
        // (the proxy will return empty NOERROR response in this mode)
        settings.block_ipv6 = true;

        DnsProxy proxy;
        auto [ret, err] = proxy.init(settings, {});
        proxy_init_result = ret;
        proxy_initialized = true;
        proxy_cond.notify_all();
        if (!proxy_init_result) {
            return;
        }

        // Wait until stopped
        {
            std::unique_lock<std::mutex> l(mtx);
            proxy_cond.wait(l, [&]() {
                return !proxy_initialized;
            });
        }

        proxy.deinit();
    });

    // Wait until the proxy is running
    {
        std::unique_lock<std::mutex> l(mtx);
        proxy_cond.wait(l, [&]() {
            return proxy_initialized.load();
        });
        if (!proxy_init_result) {
            t.join();
            FAIL() << "Proxy failed to initialize";
        }
    }

    std::atomic_long successful_requests{0};
    static std::atomic_int request_id{0};
    struct Worker {
        Worker(EventLoopPtr loop, std::future<void> future) : loop(loop), future(std::move(future)) {
            loop->start();
        }
        Worker(Worker &&other) : loop(std::exchange(other.loop, nullptr)), future(std::move(other.future)) {}
        ~Worker() {
            if (loop) {
                loop->stop();
                loop->join();
            }
        }
        void join() {
            future.get();
        }
        EventLoopPtr loop;
        std::future<void> future;
    };
    std::vector<Worker> workers;

    const auto address = fmt::format("{}[{}]:{}", listener_settings.protocol == ag::utils::TP_TCP ? "tcp://" : "",
            params.request_addr, listener_settings.port);

    for (size_t i = 0; i < params.n_threads; ++i) {
        std::this_thread::sleep_for(10ms);
        EventLoopPtr loop = EventLoop::create();
        Worker worker{loop,
        coro::to_future([](std::atomic_long &successful_requests,
                                ListenerSettings listener_settings,
                                const std::string &address,
                                size_t i,
                                auto params,
                                EventLoopPtr loop) -> coro::Task<void> {
            Logger logger{fmt::format("test_coro_{}", i)};
            SocketFactory socket_factory({*loop});
            UpstreamFactory upstream_factory({*loop, &socket_factory});

            auto upstream_res = upstream_factory.create_upstream({
                    .address = address,
                    .timeout = 1000ms,
            });

            if (upstream_res.has_error()) {
                errlog(logger, "Upstream create: {}", upstream_res.error()->str());
                co_return;
            }

            for (size_t j = 0; j < params.requests_per_thread; ++j) {
                ldns_pkt_ptr req(ldns_pkt_query_new(
                        ldns_dname_new_frm_str(params.query), LDNS_RR_TYPE_AAAA, LDNS_RR_CLASS_IN, LDNS_RD));
                ldns_pkt_set_id(req.get(), ++request_id);

                auto res = co_await upstream_res.value()->exchange(req.get());
                if (res.has_error()) {
                    errlog(logger, "[id={}] Upstream exchange: {}", ldns_pkt_id(req.get()), res.error()->str());
                    continue;
                }
                auto &resp = res.value();

                const auto rcode = ldns_pkt_get_rcode(resp.get());
                if (LDNS_RCODE_NOERROR == rcode
                        && (!ldns_pkt_tc(resp.get()) || listener_settings.protocol == ag::utils::TP_UDP)) {
                    ++successful_requests;
                } else {
                    char *str = ldns_pkt2str(resp.get());
                    errlog(logger, "[id={}] Invalid response:\n{}", ldns_pkt_id(req.get()), str);
                    std::free(str);
                }
            }
        }(successful_requests, listener_settings, address, i, params, loop))};
        workers.emplace_back(std::move(worker));
    }
    for (auto &w : workers) {
        w.join();
    }

    proxy_initialized = false; // signal proxy to stop
    proxy_cond.notify_all();
    t.join();

    ASSERT_GT(successful_requests, params.n_threads * params.requests_per_thread * .9);
}

TEST(ListenerTest, ShutsDownIfCouldNotInitialize) {
    constexpr auto addr = "12::34";
    constexpr auto port = 1;
    DnsProxy proxy;
    auto proxy_settings = DnsProxySettings::get_default();
    proxy_settings.upstreams = {{"94.140.14.140"}};
    proxy_settings.listeners = {
            {addr, port, ag::utils::TP_UDP},
            {addr, port, ag::utils::TP_TCP},
    };
    auto [ret, err] = proxy.init(proxy_settings, {});
    ASSERT_FALSE(ret);
}

INSTANTIATE_TEST_SUITE_P(ListenerLogic, ListenerTest,
        ::testing::Values(TestParams{ListenerSettings{.address = "::1", .port = 1234, .protocol = ag::utils::TP_UDP}},
                TestParams{ListenerSettings{
                        .address = "::1", .port = 1234, .protocol = ag::utils::TP_TCP, .persistent = false}},
                TestParams{ListenerSettings{.address = "::1",
                        .port = 1234,
                        .protocol = ag::utils::TP_TCP,
                        .persistent = true,
                        .idle_timeout = 1000ms}}),
        [](const testing::TestParamInfo<TestParams> &info) {
            return fmt::format("{}{}", magic_enum::enum_name(info.param.settings.protocol),
                    info.param.settings.protocol == ag::utils::TP_TCP
                            ? info.param.settings.persistent ? "_persistent" : "_not_persistent"
                            : "");
        });

} // namespace ag::dns::proxy::test
