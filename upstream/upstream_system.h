#pragma once

#include "dns/net/aio_socket.h"
#include "dns/upstream/upstream.h"

#if !defined(__ANDROID__) && !defined(_WIN32)
#include "system_resolver.h"
#endif

#include <ldns/ldns.h>
#include <memory>
#include <string>
#include <string_view>

namespace ag::dns {

/**
 * The SystemUpstream class is used for resolving DNS queries using the system resolver.
 * It supports specifying a network interface for the DNS resolution.
 *
 * The implementation is platform-specific:
 * - Apple: `upstream_system_apple.cpp`, on top of SystemResolver (a DNSService wrapper,
 *   which only yields individual records, so the reply has to be assembled by hand);
 * - Android: `upstream_system_android.cpp`, on top of `android_res_*`, which returns
 *   the raw wire reply, so it is passed through as is;
 * - Windows: `upstream_system_windows.cpp`, on top of `DnsQueryEx()` (Windows 8 and later),
 *   which only yields individual records too. The interface is specified by its index,
 *   e.g. `system://12`.
 */
class SystemUpstream : public Upstream {
public:
    /**
     * The scheme for system upstream.
     */
    static constexpr std::string_view SYSTEM_SCHEME = "system://";

    /**
     * Constructs a SystemUpstream with the given options and configuration.
     * @param opts The options for the upstream.
     * @param config The configuration for the upstream factory.
     */
    SystemUpstream(const UpstreamOptions &opts, const UpstreamFactoryConfig &config);

    /**
     * Destructor.
     */
    ~SystemUpstream() override;

private:
    /**
     * Extracts the interface name from a `system://<interface>` address.
     * @param address The upstream address.
     * @return The interface name, or an empty string if the address doesn't specify one.
     */
    static std::string interface_from_address(std::string_view address);

    /**
     * Initializes the SystemUpstream.
     * @return An error if the initialization fails, otherwise no error.
     */
    Error<InitError> init() override;

    /**
     * Exchanges DNS messages with the upstream DNS server.
     * @param request_pkt The DNS request packet.
     * @param info The DNS message info.
     * @return The result of the DNS exchange.
     */
    coro::Task<ExchangeResult> exchange(const ldns_pkt *request_pkt, const DnsMessageInfo *info) override;

    Logger m_log;            ///< The logger for this upstream.
    std::string m_interface; ///< The network interface used by this upstream.
#if defined(__ANDROID__) || defined(_WIN32)
    class Impl;
    std::unique_ptr<Impl> m_pimpl; ///< The `android_res_*` / `DnsQueryEx()` query engine used by this upstream.
#else
    std::unique_ptr<SystemResolver> m_resolver; ///< The system resolver used by this upstream.
#endif
};

} // namespace ag::dns
