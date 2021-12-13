#include <dnsproxy.h>
#include <dns64.h>
#include <dns_forwarder.h>
#include <dnsproxy_listener.h>
#include "common/logger.h"
#include <default_verifier.h>
#include <algorithm>
#include <ag_version.h>


using namespace ag;
using namespace std::chrono;

const ErrString dnsproxy::LISTENER_ERROR = "Listener failure";

static const dnsproxy_settings DEFAULT_PROXY_SETTINGS = {
    .upstreams = {
        { .address = "8.8.8.8:53", .id = 1 },
        { .address = "8.8.4.4:53", .id = 2 },
    },
    .fallbacks = {},
    .fallback_domains = {
                         // Common domains
                         "*.local",
                         "*.lan",
                         // Wi-Fi calling ePDG's
                         "epdg.epc.aptg.com.tw",
                         "epdg.epc.att.net",
                         "epdg.mobileone.net.sg",
                         "primgw.vowifina.spcsdns.net",
                         "swu-loopback-epdg.qualcomm.com",
                         "vowifi.jio.com",
                         "weconnect.globe.com.ph",
                         "wlan.three.com.hk",
                         "wo.vzwwo.com",
                         "epdg.epc.*.pub.3gppnetwork.org",
                         "ss.epdg.epc.*.pub.3gppnetwork.org",
                         // Router hosts
                         "dlinkap",
                         "dlinkrouter",
                         "edimax.setup",
                         "fritz.box",
                         "gateway.2wire.net",
                         "miwifi.com",
                         "my.firewall",
                         "my.keenetic.net",
                         "netis.cc",
                         "pocket.wifi",
                         "router.asus.com",
                         "repeater.asus.com",
                         "routerlogin.com",
                         "routerlogin.net",
                         "tendawifi.com",
                         "tendawifi.net",
                         "tplinklogin.net",
                         "tplinkwifi.net",
                         "tplinkrepeater.net",
                         },
    .dns64 = std::nullopt,
    .blocked_response_ttl_secs = 3600,
    .filter_params = {},
    .listeners = {},
    .outbound_proxy = std::nullopt,
    .block_ipv6 = false,
    .ipv6_available = true,
    .adblock_rules_blocking_mode = dnsproxy_blocking_mode::REFUSED,
    .hosts_rules_blocking_mode = dnsproxy_blocking_mode::ADDRESS,
    .dns_cache_size = 1000,
    .optimistic_cache = true,
    .enable_dnssec_ok = false,
    .enable_retransmission_handling = false,
};

const dnsproxy_settings &dnsproxy_settings::get_default() {
    return DEFAULT_PROXY_SETTINGS;
}

struct dnsproxy::impl {
    Logger log{"DNS proxy"};
    dns_forwarder forwarder;
    dnsproxy_settings settings;
    dnsproxy_events events;
    std::vector<listener_ptr> listeners;
};


dnsproxy::dnsproxy()
    : pimpl(new dnsproxy::impl)
{}

dnsproxy::~dnsproxy() = default;

std::pair<bool, ErrString> dnsproxy::init(dnsproxy_settings settings, dnsproxy_events events) {
    std::unique_ptr<impl> &proxy = this->pimpl;

    infolog(proxy->log, "Initializing proxy module...");

    proxy->settings = std::move(settings);
    proxy->events = std::move(events);

    for (upstream_options &opts : proxy->settings.fallbacks) {
        opts.ignore_proxy_settings = true;
    }

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
                errlog(proxy->log, "Failed to initialize a listener ({}): {}",
                       listener_settings.str(), error.value());
                this->deinit();
                return {false, LISTENER_ERROR};
            } else {
                proxy->listeners.push_back(std::move(listener));
            }
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

std::vector<uint8_t> dnsproxy::handle_message(ag::Uint8View message, const ag::dns_message_info *info) {
    std::unique_ptr<impl> &proxy = this->pimpl;

    std::vector<uint8_t> response = proxy->forwarder.handle_message(message, info);

    return response;
}

std::vector<std::pair<utils::transport_protocol, SocketAddress>> dnsproxy::get_listen_addresses() const {
    const impl *proxy = this->pimpl.get();

    std::vector<std::pair<utils::transport_protocol, SocketAddress>> addresses;
    addresses.reserve(proxy->listeners.size());

    for (const listener_ptr &l : proxy->listeners) {
        addresses.emplace_back(l->get_listen_address());
    }

    return addresses;
}

const char *ag::dnsproxy::version() {
    return AG_DNSLIBS_VERSION;
}
