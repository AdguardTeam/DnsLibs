#include <gtest/gtest.h>
#include <thread>
#include <atomic>
#include <dnsproxy.h>
#include <upstream.h>
#include <ldns/ldns.h>
#include <magic_enum.hpp>

using namespace std::chrono_literals;

static constexpr auto NTHREADS = 16;
static constexpr auto REQUESTS_PER_THREAD = 16;

static constexpr auto LISTEN_ADDR = "::";
static constexpr auto REQUEST_ADDR = "::1";
static constexpr auto PORT = 1234;

static constexpr auto QUERY = "google.com";

class listener_test : public ::testing::TestWithParam<ag::listener_settings> {

};

TEST_P(listener_test, listens_and_responds) {
//    ag::set_default_log_level(ag::TRACE);

    std::mutex mtx;
    std::condition_variable proxy_cond;
    std::atomic_bool proxy_initialized{false};
    std::atomic_bool proxy_init_result{false};

    const auto listener_settings = GetParam();

    std::thread t([&]() {
        auto settings = ag::dnsproxy_settings::get_default();
        settings.listeners.clear();
        settings.listeners.push_back(listener_settings);

        ag::dnsproxy proxy;
        proxy_init_result = proxy.init(settings, {});
        proxy_initialized = true;
        proxy_cond.notify_all();
        if (!proxy_init_result) {
            return;
        }

        // Wait until stopped
        {
            std::unique_lock<std::mutex> l(mtx);
            proxy_cond.wait(l, [&]() { return !proxy_initialized; });
        }

        proxy.deinit();
    });

    // Wait until the proxy is running
    {
        std::unique_lock<std::mutex> l(mtx);
        proxy_cond.wait(l, [&]() { return proxy_initialized.load(); });
        if (!proxy_init_result) {
            t.join();
            FAIL() << "Proxy failed to initialize";
        }
    }

    std::atomic_long successful_requests{0};
    std::vector<std::thread> workers;
    workers.reserve(NTHREADS);

    const auto address = fmt::format(
            "{}[{}]:{}",
            listener_settings.protocol == ag::listener_protocol::TCP ? "tcp://" : "",
            REQUEST_ADDR,
            PORT);

    for (int i = 0; i < NTHREADS; ++i) {
        std::this_thread::sleep_for(10ms);
        workers.emplace_back([&successful_requests,
                                     listener_settings,
                                     address,
                                     i]() {
            auto logger = ag::create_logger(fmt::format("test_thread_{}", i));

            auto[upstream, error] = ag::upstream::address_to_upstream(
                    address,
                    ag::upstream::options{
                            .bootstrap = {},
                            .timeout = 1000ms,
                            .server_ip = {},
                    });

            if (error) {
                logger->error("Upstream create: {}", *error);
                return;
            }

            for (int j = 0; j < REQUESTS_PER_THREAD; ++j) {
                std::this_thread::sleep_for(100ms); // Don't abuse the upstream

                ag::ldns_pkt_ptr req(
                        ldns_pkt_query_new(
                                ldns_dname_new_frm_str(QUERY),
                                LDNS_RR_TYPE_AAAA,
                                LDNS_RR_CLASS_IN,
                                LDNS_RD));

                auto[resp, error] = upstream->exchange(req.get());
                if (error) {
                    logger->error("Upstream exchange: {}", *error);
                    continue;
                }

                const auto rcode = ldns_pkt_get_rcode(resp.get());
                if (LDNS_RCODE_NOERROR == rcode
                        && (!ldns_pkt_tc(resp.get())
                                || listener_settings.protocol == ag::listener_protocol::UDP)) {
                    ++successful_requests;
                } else {
                    char *str = ldns_pkt2str(resp.get());
                    logger->error("Invalid response:\n{}", str);
                    std::free(str);
                }
            }
        });
    }
    for (auto &w : workers) {
        w.join();
    }

    proxy_initialized = false; // signal proxy to stop
    proxy_cond.notify_all();
    t.join();

    ASSERT_GT(successful_requests, NTHREADS * REQUESTS_PER_THREAD * .9);
}

TEST(listener_test, shuts_down) {
    ag::dnsproxy proxy;
    auto proxy_settings = ag::dnsproxy_settings::get_default();
    proxy_settings.listeners = {
            {LISTEN_ADDR, PORT, ag::listener_protocol::UDP},
            {LISTEN_ADDR, PORT, ag::listener_protocol::TCP, true, 1000ms},
    };
    if (proxy.init(proxy_settings, {})) {
        proxy.deinit();
    }
    SUCCEED();
}

INSTANTIATE_TEST_CASE_P(
        listener_protocols,
        listener_test,
        ::testing::Values(
                ag::listener_settings{
                        .address = LISTEN_ADDR,
                        .port = PORT,
                        .protocol = ag::listener_protocol::UDP},
                ag::listener_settings{
                        .address = LISTEN_ADDR,
                        .port = PORT,
                        .protocol = ag::listener_protocol::TCP,
                        .persistent = false},
                ag::listener_settings{
                        .address = LISTEN_ADDR,
                        .port = PORT,
                        .protocol = ag::listener_protocol::TCP,
                        .persistent = true,
                        .idle_timeout = 1000ms}),
        [](const testing::TestParamInfo<ag::listener_settings> &info) {
            return fmt::format("{}{}",
                               magic_enum::enum_name(info.param.protocol),
                               info.param.protocol == ag::listener_protocol::TCP
                               ? info.param.persistent
                                 ? "_persistent"
                                 : "_not_persistent"
                               : "");
        });
