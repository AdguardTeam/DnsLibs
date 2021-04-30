#include <dnsproxy.h>
#include <csignal>
#include <cassert>
#include <chrono>
#include <thread>
#include <atomic>

#ifdef __MACH__
#include <resolv.h>
#endif

static_assert(std::atomic_bool::is_always_lock_free, "Atomic bools are not always lock-free");
static std::atomic_bool keep_running{true};

std::vector<std::string> get_system_dns_suffixes() {
    std::vector<std::string> ret;
#ifdef __MACH__
    struct __res_state resState = {0};
    res_ninit(&resState);
    for (int i = 0; i < MAXDNSRCH; ++i) {
        if (resState.dnsrch[i]) {
            ret.emplace_back(resState.dnsrch[i]);
        }
    }
    res_nclose(&resState);
#endif
    return ret;
}

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

    settings.handle_dns_suffixes = true;
    settings.fallbacks = {{ .address = "1.1.1.1:53", .id = 1 }};
    settings.dns_suffixes = get_system_dns_suffixes();
    settings.enable_dnssec_ok = true;

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
