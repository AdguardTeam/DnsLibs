#include <atomic>
#include <cassert>
#include <chrono>
#include <csignal>
#include <thread>

#include "dns/proxy/dnsproxy.h"

using namespace ag::dns;
using ag::Logger;
using ag::LogLevel;

static_assert(std::atomic_bool::is_always_lock_free, "Atomic bools are not always lock-free");
static std::atomic_bool keep_running{true};

static void sigint_handler(int signal) {
    assert(signal == SIGINT);
    keep_running = false;
}

int main() {
    Logger::set_log_level(LogLevel::LOG_LEVEL_TRACE);
    using namespace std::chrono_literals;

    constexpr auto address = "::";
    constexpr auto port = 5321;
    constexpr auto persistent = false;
    constexpr auto idle_timeout = 3000ms;

    DnsProxySettings settings = DnsProxySettings::get_default();
    settings.listeners = {{address, port, ag::utils::TP_UDP, persistent, idle_timeout},
            {address, port, ag::utils::TP_TCP, persistent, idle_timeout}};
    //settings.upstreams = {{.address = "https://cloudflare-dns.com/dns-query", .bootstrap = {"1.1.1.1"}, .timeout = 2s}};
    //settings.upstreams = {{.address = "quic://dns.adguard.com", .bootstrap = {"1.1.1.1"}, .timeout = 2s}};
    settings.upstreams = {{.address = "94.140.14.14", .bootstrap = {}, .timeout = 2s}};
    settings.filter_params = {{{.data = "0.0.0.0 evil.com\n"
                                        "||evil.org^\n",
            .in_memory = true}}};
    settings.dns_cache_size = 0;
    settings.optimistic_cache = false;

    DnsProxy proxy;
    auto [ret, err] = proxy.init(settings, {});
    if (!ret) {
        return 1;
    }

    std::signal(SIGINT, sigint_handler);
#ifdef SIGPIPE
    std::signal(SIGPIPE, SIG_IGN);
#endif

    getchar();

    proxy.deinit();
    return 0;
}
