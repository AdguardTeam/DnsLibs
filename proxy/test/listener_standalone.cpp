#include <dnsproxy.h>
#include <csignal>
#include <cassert>
#include <chrono>
#include <thread>
#include <atomic>

static_assert(std::atomic_bool::is_always_lock_free, "Atomic bools are not always lock-free");
static std::atomic_bool keep_running{true};

static void sigint_handler(int signal) {
    assert(signal == SIGINT);
    keep_running = false;
}

int main() {
    ag::set_default_log_level(ag::log_level::TRACE);
    using namespace std::chrono_literals;

    constexpr auto address = "::";
    constexpr auto port = 1234;
    constexpr auto persistent = false;
    constexpr auto idle_timeout = 3000ms;

    ag::dnsproxy_settings settings = ag::dnsproxy_settings::get_default();
    settings.listeners = {
            {address, port, ag::listener_protocol::UDP, persistent, idle_timeout},
            {address, port, ag::listener_protocol::TCP, persistent, idle_timeout},
    };

    ag::dnsproxy proxy;
    auto [ret, err] = proxy.init(settings, {});
    if (!ret) {
        return 1;
    }

    std::signal(SIGINT, sigint_handler);
#ifdef SIGPIPE
    std::signal(SIGPIPE, SIG_IGN);
#endif

    while (keep_running) {
        std::this_thread::sleep_for(100ms);
    }

    proxy.deinit();
    return 0;
}
