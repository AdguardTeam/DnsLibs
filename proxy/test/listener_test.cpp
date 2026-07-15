#include <atomic>
#include <condition_variable>
#include <gtest/gtest.h>
#include <ldns/ldns.h>
#include <magic_enum/magic_enum.hpp>
#include <mutex>
#include <thread>

#include "common/parallel.h"
#include "dns/proxy/dnsproxy.h"
#include "dns/upstream/upstream.h"
#include "dns_test_helpers.h"
#include "loopback_dns_server.h"
#include "loopback_quic_server.h"
#include "test_certificates.h"

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

    const auto &params = GetParam();
    const auto listener_settings = params.settings;

    // A loopback upstream the proxy forwards to instead of a real public DNS
    // server. With block_ipv6 enabled below the proxy short-circuits AAAA
    // queries and never actually contacts it, but wiring a real offline
    // upstream keeps the test internet-free even if that behavior changes.
    ag::test::LoopbackDnsServer upstream_server([](const ldns_pkt &req) -> ldns_pkt_ptr {
        ldns_pkt_ptr reply = ag::test::make_base_reply(req);
        const ldns_rr *question = ldns_rr_list_rr(ldns_pkt_question(&req), 0);
        if (question != nullptr) {
            ag::test::add_a_answer(reply.get(), question);
        }
        return reply;
    });
    upstream_server.start();

    std::thread t([&]() {
        auto settings = DnsProxySettings::get_default();
        settings.upstreams = {{.address = upstream_server.address(ag::utils::TP_UDP)}};
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
        Worker(EventLoopPtr loop, std::future<void> future)
                : loop(loop)
                , future(std::move(future)) {
            loop->start();
        }
        Worker(Worker &&other) noexcept
                : loop(std::exchange(other.loop, nullptr))
                , future(std::move(other.future)) {
        }
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
        EventLoopPtr loop = EventLoop::create();
        Worker worker{loop,
                coro::to_future([](std::atomic_long &successful_requests, ListenerSettings listener_settings,
                                        const std::string &address, size_t i, auto params,
                                        EventLoopPtr loop) -> coro::Task<void> {
                    Logger logger{fmt::format("test_coro_{}", i)};
                    SocketFactory socket_factory({*loop});
                    UpstreamFactory upstream_factory({*loop, &socket_factory, false, false, 1s});

                    auto upstream_res = upstream_factory.create_upstream({.address = address});

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
                            std::free(str); // NOLINT(cppcoreguidelines-no-malloc,hicpp-no-malloc)
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
    proxy_settings.upstreams = {{"127.0.0.1"}};
    proxy_settings.listeners = {
            {addr, port, ag::utils::TP_UDP},
            {addr, port, ag::utils::TP_TCP},
    };
    auto [ret, err] = proxy.init(proxy_settings, {});
    ASSERT_FALSE(ret);
}

// Many pending requests against a local DoQ upstream. The proxy forwards 10 000
// fire-and-forget queries through a LoopbackQuicServer (DoQ mode) and a final
// query whose reply is checked. Fully offline: the server is bound to
// 127.0.0.1 (literal IP, bootstrapper bypassed), and
// on_certificate_verification accepts the loopback self-signed cert.
// Previously DISABLED_ and gated because it dialed quic://dns.adguard-dns.com;
// now un-disabled and ungated since it's deterministic and offline.
TEST(ListenerTest, ManyRequestsPending) {
    // Local DoQ upstream returning a canned A reply for any query.
    ag::test::LoopbackQuicServer upstream_server([](const ldns_pkt &req) -> ldns_pkt_ptr {
        ldns_pkt_ptr reply = ag::test::make_base_reply(req);
        const ldns_rr *question = ldns_rr_list_rr(ldns_pkt_question(&req), 0);
        if (question != nullptr) {
            ag::test::add_a_answer(reply.get(), question);
        }
        return reply;
    });
    upstream_server.start();

    bool proxy_init_result = false;
    std::mutex mtx;
    std::condition_variable proxy_cond;
    bool proxy_initialized = false;

    constexpr auto address = "::";
    constexpr auto port = 5321;
    DnsProxy proxy;
    std::thread proxy_thread([&]() {
        auto proxy_settings = DnsProxySettings::get_default();

        proxy_settings.listeners = {{address, port, ag::utils::TP_UDP}};
        // Literal-IP loopback address: bootstrapper is bypassed, DoqUpstream
        // connects directly to the in-process QUIC server.
        proxy_settings.upstreams = {{.address = upstream_server.address()}};
        proxy_settings.upstream_timeout = 3s;
        proxy_settings.enable_http3 = true;
        proxy_settings.dns_cache_size = 0;
        proxy_settings.optimistic_cache = false;

        // Accept the loopback server's self-signed certificate.
        DnsProxyEvents events;
        events.on_certificate_verification = [](CertificateVerificationEvent) -> std::optional<std::string> {
            return std::nullopt;
        };
        auto [ret, err] = proxy.init(proxy_settings, std::move(events));
        // Set the shared init result / initialized flag under the same mutex the
        // waits use, to avoid a data race and missed wakeups.
        {
            std::lock_guard<std::mutex> l(mtx);
            proxy_init_result = ret;
            proxy_initialized = true;
        }
        proxy_cond.notify_all();

        // Seed two fire-and-forget queries so there are in-flight requests
        // when the main thread launches the 10 000-query storm below.
        //
        // handle_message is a coroutine: it captures its Uint8View argument,
        // suspends on `co_await m_loop->co_submit()` and only reads the view
        // later on the event loop thread. coro::run_detached() resumes the
        // coroutine synchronously up to that first suspension, so the view
        // must stay valid until handle_message finishes. The original test
        // reused one stack-local ldns_buffer and reset it between the two
        // requests, freeing the data the suspended handle_message still
        // referenced — a heap-use-after-free caught by ASan.
        //
        // The wire data is therefore moved into the coroutine itself as a
        // by-value parameter. Coroutine parameters live in the heap-allocated
        // coroutine frame and are destroyed only when the coroutine finishes,
        // so the Uint8View into that data stays valid across the suspension.
        // (Capturing the buffer in the *lambda* would not work: a lambda
        // coroutine's captures live in the temporary closure object, which is
        // destroyed as soon as run_detached() returns — dangling the data the
        // still-suspended handle_message references.)
        auto fire_forget = [](DnsProxy &proxy, const char *name) {
            ldns_pkt_ptr reqpkt(
                    ldns_pkt_query_new(ldns_dname_new_frm_str(name), LDNS_RR_TYPE_A, LDNS_RR_CLASS_IN, LDNS_RD));
            ldns_buffer_ptr buf{ldns_buffer_new(REQUEST_BUFFER_INITIAL_CAPACITY)};
            ldns_pkt2buffer_wire(buf.get(), reqpkt.get());
            const uint8_t *base = ldns_buffer_at(buf.get(), 0);
            Uint8Vector data{base, base + ldns_buffer_position(buf.get())};
            ag::coro::run_detached([](DnsProxy &proxy, Uint8Vector data) -> ag::coro::Task<void> {
                co_await proxy.handle_message(Uint8View{data.data(), data.size()}, nullptr);
            }(proxy, std::move(data)));
        };
        fire_forget(proxy, "youtube.com");
        fire_forget(proxy, "vk.com");

        // Wait until stopped
        {
            std::unique_lock<std::mutex> l(mtx);
            proxy_cond.wait(l, [&]() {
                return !proxy_initialized;
            });
        }
    });

    // Wait until the proxy is initialized (replaces a fixed 2 s sleep). Capture
    // the init result under the same lock so the assertion below reads a value
    // free of data races (rather than reading the shared flag unlocked).
    bool proxy_init_result_local = false;
    {
        std::unique_lock<std::mutex> l(mtx);
        proxy_cond.wait(l, [&]() {
            return proxy_initialized;
        });
        proxy_init_result_local = proxy_init_result;
    }
    ASSERT_TRUE(proxy_init_result_local);

    ldns_pkt_ptr reqpkt(ldns_pkt_query_new(ldns_dname_new_frm_str("g.co"), LDNS_RR_TYPE_A, LDNS_RR_CLASS_IN, LDNS_RD));
    ldns_buffer_ptr buffer{ldns_buffer_new(REQUEST_BUFFER_INITIAL_CAPACITY)};
    ldns_pkt2buffer_wire(buffer.get(), reqpkt.get());

    // Launch the 10 000-request "many pending" storm as fire-and-forget
    // coroutines, awaited via an atomic counter + condition_variable barrier
    // instead of sleep(). Pass buffer/counter/cv as parameters, not captures.
    constexpr int TOTAL_REQUESTS = 10000;
    std::mutex storm_mtx;
    std::condition_variable storm_cv;
    std::atomic<int> storm_pending{TOTAL_REQUESTS};

    for (int i = 0; i < TOTAL_REQUESTS; ++i) {
        ag::coro::run_detached([](DnsProxy &proxy, ldns_buffer *buffer, std::atomic<int> &pending,
                                       std::condition_variable &cv) -> ag::coro::Task<void> {
            co_await proxy.handle_message({ldns_buffer_at(buffer, 0), ldns_buffer_position(buffer)}, nullptr);
            if (pending.fetch_sub(1, std::memory_order_acq_rel) == 1) {
                cv.notify_one();
            }
            co_return;
        }(proxy, buffer.get(), std::ref(storm_pending), std::ref(storm_cv)));
    }

    // Bounded wait: a regression that never completes surfaces as an
    // ASSERT failure here instead of hanging the test binary. The predicate
    // guards against lost wakeups: the last worker sets pending to 0 before
    // calling notify_one(), so a notify that races ahead of the wait is still
    // observed via the re-checked predicate on entry.
    {
        std::unique_lock<std::mutex> lk(storm_mtx);
        storm_cv.wait_for(lk, 30s, [&] {
            return storm_pending.load() == 0;
        });
    }
    ASSERT_EQ(storm_pending.load(), 0) << "not all " << TOTAL_REQUESTS << " storm requests completed in time";

    // Send a new request after the storm and await its result directly instead
    // of sleeping for a fixed 3 s. This is race-free: the storm above has
    // fully resolved before the buffer is reused.
    ldns_pkt_ptr reqpkt2(
            ldns_pkt_query_new(ldns_dname_new_frm_str("google.com"), LDNS_RR_TYPE_A, LDNS_RR_CLASS_IN, LDNS_RD));

    buffer.reset(ldns_buffer_new(REQUEST_BUFFER_INITIAL_CAPACITY));
    ldns_pkt2buffer_wire(buffer.get(), reqpkt2.get());

    // Pass `buffer` as a by-value parameter, not a capture.
    Uint8Vector last_reply_res = coro::to_future([](DnsProxy &proxy, ldns_buffer *buffer) -> coro::Task<Uint8Vector> {
        co_return co_await proxy.handle_message({ldns_buffer_at(buffer, 0), ldns_buffer_position(buffer)}, nullptr);
    }(proxy, buffer.get()))
                                         .get();

    // check if last request got correct response
    ASSERT_FALSE(last_reply_res.empty());
    ldns_pkt *reply_pkt = nullptr;
    auto status = ldns_wire2pkt(&reply_pkt, last_reply_res.data(), last_reply_res.size());
    ASSERT_EQ(LDNS_STATUS_OK, status) << ldns_get_errorstr_by_id(status);
    ldns_pkt_free(reply_pkt);

    // Signal the proxy thread to stop. Guard the shared flag with the same mutex
    // its wait predicate reads under, then notify.
    {
        std::lock_guard<std::mutex> l(mtx);
        proxy_initialized = false;
    }
    proxy_cond.notify_one();
    proxy.deinit();
    proxy_thread.join();
    upstream_server.stop();
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
