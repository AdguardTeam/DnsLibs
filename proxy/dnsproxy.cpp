#include "dns/proxy/dnsproxy.h"

#include <memory>
#include <optional>
#include <utility>
#include <vector>

#ifdef __APPLE__
#include <sys/qos.h>
#include <TargetConditionals.h>
#endif // __APPLE__

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
                        "b._dns-sd._udp.*.in-addr.arpa",
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
        .block_h3_alpn = false,
        .enable_route_resolver = false,
        .enable_parallel_upstream_queries = false,
        .enable_fallback_on_upstreams_failure = true,
        .enable_servfail_on_upstreams_failure = false,
        .enable_http3 = false,
        .enable_post_quantum_cryptography = true,
#if defined(__APPLE__) && TARGET_OS_IPHONE
        .qos_settings = {
            .qos_class = QOS_CLASS_DEFAULT,
            .relative_priority = 0,
        }
#endif // __APPLE__ && TARGET_OS_IPHONE
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
    std::shared_ptr<DnsFilterManager> filter_manager;
    std::shared_ptr<bool> shutdown_guard;
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

    // Propagate post-quantum setting to all upstreams
    for (UpstreamOptions &opts : proxy->settings.upstreams) {
        opts.enable_post_quantum_cryptography = proxy->settings.enable_post_quantum_cryptography;
    }
    for (UpstreamOptions &opts : proxy->settings.fallbacks) {
        opts.enable_post_quantum_cryptography = proxy->settings.enable_post_quantum_cryptography;
    }
    if (proxy->settings.dns64.has_value()) {
        for (UpstreamOptions &opts : proxy->settings.dns64->upstreams) {
            opts.enable_post_quantum_cryptography = proxy->settings.enable_post_quantum_cryptography;
        }
    }

    proxy->shutdown_guard = std::make_shared<bool>(true);
    proxy->loop = EventLoop::create();
    if (!proxy->loop) {
        this->deinit();
        return {false, make_error(DnsProxyInitError::AE_EVENT_LOOP_NOT_SET, "Failed to create event loop")};
    }

    proxy->forwarder.emplace();

    proxy->filter_manager = std::make_shared<DnsFilterManager>();
    auto [result, err_or_warn] = proxy->filter_manager->init(proxy->settings);
    if (!result) {
        proxy->filter_manager.reset();
        this->deinit();
        dbglog(proxy->log, "Filter init failed: {}", err_or_warn->str());
        return {false, err_or_warn};
    }
    auto err = proxy->forwarder->init(proxy->loop, proxy->settings, proxy->events, proxy->filter_manager);
    if (err) {
        proxy->forwarder.reset();
        this->deinit();
        dbglog(proxy->log, "Forwarder init failed: {}", err->str());
        return {false, err};
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

    proxy->loop->start({
#if defined(__APPLE__) && TARGET_OS_IPHONE
        .qos_class = proxy->settings.qos_settings.qos_class,
        .qos_relative_priority = proxy->settings.qos_settings.relative_priority
#endif // __APPLE__ && TARGET_OS_IPHONE
    });

    infolog(proxy->log, "Proxy module initialized");
    return {true, err_or_warn};
}

void DnsProxy::deinit() {
    std::unique_ptr<Impl> &proxy = m_pimpl;

    proxy->shutdown_guard.reset();
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

        if (proxy->filter_manager) {
            proxy->filter_manager->deinit();
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

DnsProxy::DnsProxyInitResult DnsProxy::reapply_settings_internal(
        DnsProxySettings settings, ReapplyOptions reapply_options) {
    std::unique_ptr<Impl> &proxy = m_pimpl;

    infolog(proxy->log, "Reapplying settings, reapply_options={}", int(reapply_options));

    if (!reapply_options) {
        dbglog(proxy->log, "Nothing to reapply");
        return {true, {}};
    }

    Error<DnsProxyInitError> warning;
    std::shared_ptr<DnsFilterManager> new_filter_manager;

    if (reapply_options & RO_SETTINGS) {
        // Update everything except listeners and filter_params
        auto saved_listeners = std::move(proxy->settings.listeners);
        auto saved_filter_params = std::move(proxy->settings.filter_params);
        proxy->settings = std::move(settings);
        proxy->settings.listeners = std::move(saved_listeners);
        if (!(reapply_options & RO_FILTERS)) {
            proxy->settings.filter_params = std::move(saved_filter_params);
        }
    } else if (reapply_options & RO_FILTERS) {
        // Update only filter_params
        proxy->settings.filter_params = std::move(settings.filter_params);
    }

    if (reapply_options & RO_FILTERS) {
        new_filter_manager = std::make_shared<DnsFilterManager>();
        auto [result, err_or_warn] = new_filter_manager->init(proxy->settings);
        if (!result) {
            dbglog(proxy->log, "Filter init failed: {}", err_or_warn->str());
            new_filter_manager->deinit();
            new_filter_manager.reset();
            return {false, err_or_warn};
        }
        warning = err_or_warn;
    }

    if (reapply_options & RO_SETTINGS) {
        if (proxy->forwarder) {
            proxy->forwarder->deinit();
            proxy->forwarder.reset();
        }
    }

    if (reapply_options & RO_FILTERS) {
        proxy->filter_manager->deinit();
        proxy->filter_manager.reset();
        proxy->filter_manager = new_filter_manager;

        if (proxy->forwarder && !(reapply_options & RO_SETTINGS)) {
            proxy->forwarder->clear_cache();
            proxy->forwarder->update_filter_manager(proxy->filter_manager);
        }
    }

    if (reapply_options & RO_SETTINGS) {
        proxy->forwarder.emplace();
        auto forwarder_err = proxy->forwarder->init(proxy->loop, proxy->settings, proxy->events, proxy->filter_manager);
        if (forwarder_err) {
            proxy->forwarder.reset();
            dbglog(proxy->log, "Forwarder init failed: {}", forwarder_err->str());
            return {false, forwarder_err};
        }
    }

    infolog(proxy->log, "Settings reapplied successfully");
    return {true, warning};
}

DnsProxy::DnsProxyInitResult DnsProxy::reapply_settings(DnsProxySettings settings, ReapplyOptions reapply_options) {
    std::unique_ptr<Impl> &proxy = m_pimpl;

    if (!proxy->loop) {
        return {false, make_error(DnsProxyInitError::AE_PROXY_NOT_SET)};
    }

    auto future = proxy->loop->async<DnsProxyInitResult>(
            [this, settings = std::move(settings), reapply_options](auto promise) mutable {
                promise->set_value(reapply_settings_internal(std::move(settings), reapply_options));
            });

    return future.get();
}

const DnsProxySettings &DnsProxy::get_settings() const {
    return m_pimpl->settings;
}

bool DnsProxy::match_fallback_domains_internal(Uint8View message) const {
    const std::unique_ptr<Impl> &proxy = m_pimpl;

    if (!proxy->filter_manager) {
        return false;
    }

    return proxy->filter_manager->match_fallback_domains(message);
}

bool DnsProxy::match_fallback_domains(ag::Uint8View message) const {
    const std::unique_ptr<Impl> &proxy = m_pimpl;
    auto action = [this, message]() mutable {
        return this->match_fallback_domains_internal(message);
    };
    return proxy->loop->async<bool>(action).get();
}

coro::Task<Uint8Vector> DnsProxy::handle_message_internal(Uint8View message, const DnsMessageInfo *info) {
    std::unique_ptr<Impl> &proxy = m_pimpl;

    Uint8Vector response = co_await proxy->forwarder->handle_message(message, info);

    co_return response;
}

coro::Task<Uint8Vector> DnsProxy::handle_message(Uint8View message, const DnsMessageInfo *info) {
    std::unique_ptr<Impl> &proxy = m_pimpl;

    std::weak_ptr<bool> guard = proxy->shutdown_guard;
    co_await proxy->loop->co_submit();
    if (guard.expired() || !proxy->forwarder) {
        co_return {};
    }

    co_return co_await handle_message_internal(message, info);
}

Uint8Vector DnsProxy::handle_message_sync(Uint8View message, const DnsMessageInfo *info) {
    return coro::to_future(handle_message(message, info)).get();
}

const char *DnsProxy::version() {
    return AG_DNSLIBS_VERSION;
}

} // namespace ag::dns
