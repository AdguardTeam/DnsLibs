#include <gtest/gtest.h>

#include "common/coro.h"
#include "common/parallel.h"
#include "dns/common/event_loop.h"

namespace ag::dns::test {

TEST(EventLoop, Submit) {
    static Logger log("Submit");
    auto loop = EventLoop::create();
    auto f = loop->async<int>([loop]() {
        infolog(log, "Hello!");
        loop->stop();
        return 42;
    });
    loop->start();
    infolog(log, "Result is: {}", f.get());
    loop->join();
}

TEST(EventLoop, Coro) {
    static Logger log("Coro");
    auto loop = EventLoop::create();
    auto f = coro::to_future([](EventLoop &loop) -> coro::Task<int> {
        infolog(log, "Hello from outside the loop");
        co_await loop.co_submit();
        infolog(log, "Hello from inside the loop");
        using namespace std::chrono_literals;
        for (int i = 0; i < 5; i++) {
            infolog(log, "co_sleep test: {}", i);
            co_await loop.co_sleep(200ms * i);
        }
        infolog(log, "co_sleep test done");
        infolog(log, "any_of_void test, 1.5s and 4s");
        co_await parallel::any_of(loop.co_sleep(1500ms), loop.co_sleep(4s));
        infolog(log, "any_of_void test done");
        infolog(log, "all_of_void test, 1.5s and 4s");
        co_await parallel::all_of(loop.co_sleep(1500ms), loop.co_sleep(4s));
        infolog(log, "all_of_void test done");
        loop.stop();
        co_return 42;
    }(*loop));
    loop->start();
    infolog(log, "Result is: {}", f.get());
    loop->join();
}

} // namespace ag::dns::test
