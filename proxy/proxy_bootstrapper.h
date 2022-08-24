#pragma once

#include "common/coro.h"
#include "common/defs.h"
#include "common/error.h"
#include "common/logger.h"
#include "dns/common/event_loop.h"
#include "dns/net/certificate_verifier.h"
#include "dns/net/socket.h"
#include "dns/proxy/dnsproxy_settings.h"
#include "dns/upstream/bootstrapper.h"
#include "dns/upstream/upstream.h"

namespace ag::dns {

struct ProxyBootstrapper : public SocketFactory::ProxyBootstrapper {
    SocketFactory socket_factory;
    /// Configuration of the upstream factory which creates resolving upstream
    UpstreamFactoryConfig upstream_config;
    Logger log{"Proxy bootstrapper"};

    ProxyBootstrapper(EventLoop &loop, const DnsProxySettings &settings, const DnsProxyEvents &events)
            : socket_factory({
                    .loop = loop,
                    .verifier = (events.on_certificate_verification != nullptr)
                            ? std::unique_ptr<CertificateVerifier>(
                                    new ApplicationVerifier(events.on_certificate_verification))
                            : std::unique_ptr<CertificateVerifier>(new DefaultVerifier),
                    .enable_route_resolver = settings.enable_route_resolver,
            })
            , upstream_config(UpstreamFactoryConfig{
                      .loop = loop,
                      .socket_factory = &this->socket_factory,
                      .ipv6_available = settings.ipv6_available,
              }) {
    }

    ~ProxyBootstrapper() override = default;

    ProxyBootstrapper(const ProxyBootstrapper &) = delete;
    ProxyBootstrapper &operator=(const ProxyBootstrapper &) = delete;
    ProxyBootstrapper(ProxyBootstrapper &&) = delete;
    ProxyBootstrapper &operator=(ProxyBootstrapper &&) = delete;

    bool resolve(std::string_view host, const std::vector<std::string> &bootstrap, Millis timeout,
            IfIdVariant outbound_interface, Callback callback) override {
        Bootstrapper bs({
                .address_string = host,
                .bootstrap = bootstrap,
                .timeout = timeout,
                .upstream_config = this->upstream_config,
                .outbound_interface = std::move(outbound_interface),
        });

        if (Error<Bootstrapper::BootstrapperError> error = bs.init(); error != nullptr) {
            warnlog(this->log, "Failed to initialize underlying bootstrapper: {}", error->str());
            return false;
        }

        coro::run_detached([](Logger log_, Bootstrapper bs, Callback cb) -> coro::Task<void> {
            Bootstrapper::ResolveResult result = co_await bs.get();

            std::optional<SocketAddress> resolved;
            if (result.error != nullptr) {
                warnlog(log_, "Bootstrap failure: {}", result.error->str());
            } else if (result.addresses.empty()) {
                warnlog(log_, "Bootstrapped to empty list");
            } else {
                resolved = std::make_optional(result.addresses.front());
            }
            cb(resolved);
        }(this->log, std::move(bs), std::move(callback)));

        return true;
    }
};

} // namespace ag::dns
