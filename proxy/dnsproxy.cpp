#include "dns/proxy/dnsproxy.h"

#include <memory>
#include <optional>
#include <utility>
#include <vector>

#include "common/coro.h"
#include "common/defs.h"
#include "common/logger.h"
#include "dns/common/dns_utils.h"
#include "dns/common/event_loop.h"
#include "dns/common/version.h"
#include "dns/proxy/dnsproxy_events.h"
#include "dns/proxy/dnsproxy_settings.h"
#include "dns/upstream/upstream.h"
#include "dns_forwarder.h"
#include "dnsproxy_listener.h"

using namespace std::chrono;

namespace ag::dns {

static const DnsProxySettings DEFAULT_PROXY_SETTINGS = {
        .upstreams = {},
        .fallbacks = {},
        .fallback_domains =
                {
                        // Common domains
                        "*.local",
                        "*.lan",
                        // DNS Service Discovery
                        "lb._dns-sd._udp.*.in-addr.arpa",
                        "*.service.arpa",
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
                        "dengon.docomo.ne.jp",
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
                        "oppowifi.com",
                        "myrepeater.net",
                        "mywifi.net",
                        "setup.pix-link.net",
                        "tplinkdeco.net",
                        "tplinkextender.net",
                        "www.asusrouter.com",
                },
        .dns64 = std::nullopt,
        .blocked_response_ttl_secs = 3600,
        .filter_params = {},
        .listeners = {},
        .outbound_proxy = std::nullopt,
        .block_ipv6 = false,
        .ipv6_available = true,
#ifdef _WIN32
        // On Windows, a funky RCODE leads to issues with the system resolver
        // trying other servers and AdGuard VPN blocking those requests.
        .adblock_rules_blocking_mode = DnsProxyBlockingMode::UNSPECIFIED_ADDRESS,
#else
        .adblock_rules_blocking_mode = DnsProxyBlockingMode::REFUSED,
#endif
        .hosts_rules_blocking_mode = DnsProxyBlockingMode::ADDRESS,
        .dns_cache_size = 1000,
        .optimistic_cache = true,
        .enable_dnssec_ok = false,
        .enable_retransmission_handling = false,
        .block_ech = false,
        .enable_route_resolver = false,
        .enable_parallel_upstream_queries = false,
        .enable_fallback_on_upstreams_failure = true,
        .enable_servfail_on_upstreams_failure = true,
        .enable_http3 = false,
};

const DnsProxySettings &DnsProxySettings::get_default() {
    return DEFAULT_PROXY_SETTINGS;
}

struct DnsProxy::Impl {
    Logger log{"DNS proxy"};
    EventLoopPtr loop;
    std::optional<DnsForwarder> forwarder;
    DnsProxySettings settings;
    DnsProxyEvents events;
    std::vector<ListenerPtr> listeners;
};

DnsProxy::DnsProxy()
        : m_pimpl(new DnsProxy::Impl) {
}

DnsProxy::~DnsProxy() = default;

DnsProxy::DnsProxyInitResult DnsProxy::init(DnsProxySettings settings, DnsProxyEvents events) {
    std::unique_ptr<Impl> &proxy = m_pimpl;

    infolog(proxy->log, "Initializing proxy module...");

    proxy->settings = std::move(settings);
    proxy->events = std::move(events);

    for (UpstreamOptions &opts : proxy->settings.fallbacks) {
        opts.ignore_proxy_settings = true;
    }

    proxy->loop = EventLoop::create();
    proxy->forwarder.emplace();
    auto [result, err_or_warn] = proxy->forwarder->init(proxy->loop, proxy->settings, proxy->events);
    if (!result) {
        proxy->forwarder.reset();
        this->deinit();
        dbglog(proxy->log, "Forwarder init failed: {}", err_or_warn->str());
        return {false, err_or_warn};
    }

    if (!proxy->settings.listeners.empty()) {
        infolog(proxy->log, "Initializing listeners...");
        proxy->listeners.reserve(proxy->settings.listeners.size());
        for (auto &listener_settings : proxy->settings.listeners) {
            auto create_result = DnsProxyListener::create_and_listen(listener_settings, this, proxy->loop.get());
            if (create_result.has_error()) {
                this->deinit();
                return {false, create_result.error()};
            }
            // In case the port was 0 in settings, save the actual port the listener's bound to.
            listener_settings.port = create_result.value()->get_listen_address().second.port();
            proxy->listeners.push_back(std::move(create_result.value()));
        }
    }

    proxy->loop->start();

    infolog(proxy->log, "Proxy module initialized");
    return {true, err_or_warn};
}

void DnsProxy::deinit() {
    std::unique_ptr<Impl> &proxy = m_pimpl;
    if (proxy->loop == nullptr) {
        infolog(proxy->log, "Proxy module is not initialized, deinitialization is not needed");
        return;
    }
    proxy->loop->start();
    proxy->loop->submit([this] {
        std::unique_ptr<Impl> &proxy = m_pimpl;
        infolog(proxy->log, "Deinitializing proxy module...");

        infolog(proxy->log, "Shutting down listeners...");
        proxy->listeners.clear();
        infolog(proxy->log, "Shutting down listeners done");

        if (proxy->forwarder) {
            proxy->forwarder->deinit();
        }

        infolog(proxy->log, "Stopping event loop");
        proxy->loop->stop();
        infolog(proxy->log, "Stopping event loop done");
    });
    infolog(proxy->log, "Joining event loop");
    proxy->loop->join();
    infolog(proxy->log, "Joining event loop done");
    infolog(proxy->log, "Proxy module deinitialized");
    proxy->settings = {};
}

const DnsProxySettings &DnsProxy::get_settings() const {
    return m_pimpl->settings;
}

coro::Task<Uint8Vector> DnsProxy::handle_message(Uint8View message, const DnsMessageInfo *info) {
    std::unique_ptr<Impl> &proxy = m_pimpl;

    Uint8Vector response = co_await proxy->forwarder->handle_message(message, info);

    co_return response;
}

Uint8Vector DnsProxy::handle_message_sync(Uint8View message, const DnsMessageInfo *info) {
    return coro::to_future(handle_message(message, info)).get();
}

const char *DnsProxy::version() {
    return AG_DNSLIBS_VERSION;
}

} // namespace ag::dns
