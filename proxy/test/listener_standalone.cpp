#include <atomic>
#include <cassert>
#include <chrono>
#include <csignal>
#include <thread>

#ifdef _WIN32
#include <cstdio>
#endif

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
#ifdef _WIN32
    constexpr auto port = 53;
#else
    constexpr auto port = 5321;
#endif
    constexpr auto persistent = true;
    constexpr auto idle_timeout = 60000ms;

    DnsProxySettings settings = DnsProxySettings::get_default();
    settings.listeners = {
            {address, port, ag::utils::TP_UDP, persistent, idle_timeout},
            {address, port, ag::utils::TP_TCP, persistent, idle_timeout},
    };
    settings.upstreams = {{
            .address = "94.140.14.14",
            .bootstrap = {},
            .resolved_server_ip = std::monostate{},
            .id = 42,
            .outbound_interface = std::monostate{},
            .ignore_proxy_settings = false,
    }};
    settings.filter_params = {{
            {
                    .id = 42,
                    .data = "0.0.0.0 evil.com\n",
                    .in_memory = true,
            },
            {
                    .id = 43,
                    .data = "||evil.org^\n",
                    .in_memory = true,
            },
    }};
    settings.dns_cache_size = 0;
    settings.optimistic_cache = false;
    settings.enable_http3 = false;

    DnsProxyEvents events{};

#ifdef _WIN32
    events.on_certificate_verification = [](CertificateVerificationEvent) {
        return std::nullopt;
    };
#endif

    DnsProxy proxy;
    auto [ret, err] = proxy.init(std::move(settings), std::move(events));
    if (!ret) {
        return 1;
    }

    std::signal(SIGINT, sigint_handler);
#ifdef SIGPIPE
    std::signal(SIGPIPE, SIG_IGN);
#endif

    fprintf(stderr, "My PID: %d\n", getpid());

#ifdef _WIN32
    // Put the helper into the working directory to automatically set and restrict DNS to loopback.
    // Note: `-Verb RunAs` prevents environment inheritance.
    auto cmd = AG_FMT(
            R"(powershell -Command "Start-Process adguard-win-dns-helper.exe -ArgumentList \"{} 127.0.0.1 ::1\" -Verb RunAs")",
            getpid());
    FILE *helper = _popen(cmd.c_str(), "w");
#endif

    while (keep_running) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

#ifdef _WIN32
    if (helper) {
        _pclose(helper);
    }
#endif

    proxy.deinit();
    return 0;
}
