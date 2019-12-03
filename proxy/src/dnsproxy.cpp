#include <dnsproxy.h>
#include <dns64.h>
#include <dns_forwarder.h>
#include <ag_logger.h>
#include <ag_utils.h>

#include <mutex>
#include <thread>


using namespace ag;
using namespace std::chrono;

static constexpr milliseconds DEFAULT_UPSTREAM_TIMEOUT = milliseconds(30000);

static const dnsproxy_settings DEFAULT_PROXY_SETTINGS = {
    .upstreams = {
        { "8.8.8.8:53", { {}, DEFAULT_UPSTREAM_TIMEOUT, {} } },
        { "8.8.4.4:53", { {}, DEFAULT_UPSTREAM_TIMEOUT, {} } },
    },
    .dns64 = std::nullopt,
    .blocked_response_ttl = 3600,
    .filter_params = {},
};

const dnsproxy_settings &dnsproxy_settings::get_default() {
    return DEFAULT_PROXY_SETTINGS;
}

struct dnsproxy::impl {
    ag::logger log;
    dns_forwarder forwarder;
    dnsproxy_settings settings;
    dnsproxy_events events;
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

    if (!proxy->forwarder.init(proxy->settings)) {
        this->deinit();
        return false;
    }

    infolog(proxy->log, "Proxy module initialized");
    return true;
}

void dnsproxy::deinit() {
    std::unique_ptr<impl> &proxy = this->pimpl;
    proxy->forwarder.deinit();
    proxy->settings = {};
}

const dnsproxy_settings &dnsproxy::get_settings() const {
    return this->pimpl->settings;
}

std::vector<uint8_t> dnsproxy::handle_message(ag::uint8_view message) {
    std::unique_ptr<impl> &proxy = this->pimpl;

    dns_request_processed_event event = {};
    event.start_time = duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();

    dns_forwarder::result result = proxy->forwarder.handle_message(message, event);

    event.elapsed = duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count() - event.start_time;
    if (err_string err = result.second; err.has_value()) {
        event.error = err.value();
    }
    if (proxy->events.on_request_processed != nullptr) {
        proxy->events.on_request_processed(std::move(event));
    }

    return result.first;
}
