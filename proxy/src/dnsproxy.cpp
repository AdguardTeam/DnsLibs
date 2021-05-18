#include <dnsproxy.h>
#include <dns64.h>
#include <dns_forwarder.h>
#include <dnsproxy_listener.h>
#include <ag_logger.h>
#include <default_verifier.h>
#include <algorithm>
#include <ag_version.h>


using namespace ag;
using namespace std::chrono;

static const dnsproxy_settings DEFAULT_PROXY_SETTINGS = {
    .upstreams = {
        { .address = "8.8.8.8:53", .id = 1 },
        { .address = "8.8.4.4:53", .id = 2 },
    },
    .fallbacks = {},
    .handle_dns_suffixes = false,
    .dns_suffixes = {},
    .dns64 = std::nullopt,
    .blocked_response_ttl_secs = 3600,
    .filter_params = {},
    .listeners = {},
    .outbound_proxy = std::nullopt,
    .block_ipv6 = false,
    .ipv6_available = true,
    .blocking_mode = dnsproxy_blocking_mode::DEFAULT,
    .dns_cache_size = 1000,
    .optimistic_cache = true,
    .enable_dnssec_ok = false
};

const dnsproxy_settings &dnsproxy_settings::get_default() {
    return DEFAULT_PROXY_SETTINGS;
}

struct dnsproxy::impl {
    logger log;
    dns_forwarder forwarder;
    dnsproxy_settings settings;
    dnsproxy_events events;
    std::vector<listener_ptr> listeners;
};


dnsproxy::dnsproxy()
    : pimpl(new dnsproxy::impl)
{}

dnsproxy::~dnsproxy() = default;

std::pair<bool, err_string> dnsproxy::init(dnsproxy_settings settings, dnsproxy_events events) {
    std::unique_ptr<impl> &proxy = this->pimpl;
    pimpl->log = ag::create_logger("DNS proxy");

    infolog(proxy->log, "Initializing proxy module...");

    proxy->settings = std::move(settings);
    proxy->events = std::move(events);

    auto [result, err_or_warn] = proxy->forwarder.init(proxy->settings, proxy->events);
    if (!result) {
        this->deinit();
        return {false, err_or_warn};
    }

    if (!proxy->settings.listeners.empty()) {
        infolog(proxy->log, "Initializing listeners...");
        proxy->listeners.reserve(proxy->settings.listeners.size());
        for (const auto &listener_settings : proxy->settings.listeners) {
            auto[listener, error] = dnsproxy_listener::create_and_listen(listener_settings, this);
            if (error.has_value()) {
                errlog(proxy->log, "Failed to create a listener {}: {}", listener_settings.str(), error.value());
            } else {
                proxy->listeners.push_back(std::move(listener));
            }
        }
        if (proxy->listeners.empty()) {
            auto err = "Failed to initialize any listeners";
            errlog(proxy->log, "{}", err);
            this->deinit();
            return {false, err};
        }
    }

    infolog(proxy->log, "Proxy module initialized");
    return {true, std::move(err_or_warn)};
}

void dnsproxy::deinit() {
    std::unique_ptr<impl> &proxy = this->pimpl;
    infolog(proxy->log, "Deinitializing proxy module...");

    infolog(proxy->log, "Shutting down listeners...");
    for (auto& listener : proxy->listeners) {
        listener->shutdown();
    }
    // Must wait for all listeners to shut down before destroying the forwarder
    // (there may still be requests in process after a shutdown() call)
    for (auto& listener : proxy->listeners) {
        listener->await_shutdown();
    }
    infolog(proxy->log, "Done");

    proxy->forwarder.deinit();
    proxy->settings = {};
    infolog(proxy->log, "Proxy module deinitialized");
}

const dnsproxy_settings &dnsproxy::get_settings() const {
    return this->pimpl->settings;
}

std::vector<uint8_t> dnsproxy::handle_message(ag::uint8_view message) {
    std::unique_ptr<impl> &proxy = this->pimpl;

    std::vector<uint8_t> response = proxy->forwarder.handle_message(message);

    return response;
}

const char *ag::dnsproxy::version() {
    return AG_DNSLIBS_VERSION;
}
