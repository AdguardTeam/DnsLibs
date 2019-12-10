#include <dnsproxy.h>
#include <dns64.h>
#include <dns_forwarder.h>
#include <dnsproxy_listener.h>
#include <ag_logger.h>
#include <default_verifier.h>


using namespace ag;
using namespace std::chrono;

static constexpr milliseconds DEFAULT_UPSTREAM_TIMEOUT(1000);

static const dnsproxy_settings DEFAULT_PROXY_SETTINGS = {
    .upstreams = {
        { "8.8.8.8:53", {}, DEFAULT_UPSTREAM_TIMEOUT, {} },
        { "8.8.4.4:53", {}, DEFAULT_UPSTREAM_TIMEOUT, {} },
    },
    .dns64 = std::nullopt,
    .blocked_response_ttl = 3600,
    .filter_params = {},
    .listeners = {}
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

bool dnsproxy::init(dnsproxy_settings settings, dnsproxy_events events) {
    std::unique_ptr<impl> &proxy = this->pimpl;
    pimpl->log = ag::create_logger("DNS proxy");

    infolog(proxy->log, "Initializing proxy module...");

    proxy->settings = std::move(settings);
    proxy->events = std::move(events);

    if (!proxy->forwarder.init(proxy->settings, proxy->events)) {
        this->deinit();
        return false;
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
            errlog(proxy->log, "Failed to initialize any listeners");
            this->deinit();
            return false;
        }
    }

    infolog(proxy->log, "Proxy module initialized");
    return true;
}

void dnsproxy::deinit() {
    std::unique_ptr<impl> &proxy = this->pimpl;
    infolog(proxy->log, "Deinitializing proxy module...");
    for (auto& listener : proxy->listeners) {
        listener->shutdown();
    }
    // Must wait for all listeners to shut down before destroying the forwarder
    // (there may still be requests in process after a shutdown() call)
    for (auto& listener : proxy->listeners) {
        listener->await_shutdown();
    }
    proxy->forwarder.deinit();
    proxy->settings = {};
    infolog(proxy->log, "Proxy module deinitialized...");
}

const dnsproxy_settings &dnsproxy::get_settings() const {
    return this->pimpl->settings;
}

std::vector<uint8_t> dnsproxy::handle_message(ag::uint8_view message) {
    std::unique_ptr<impl> &proxy = this->pimpl;

    std::vector<uint8_t> response = proxy->forwarder.handle_message(message);

    return response;
}
