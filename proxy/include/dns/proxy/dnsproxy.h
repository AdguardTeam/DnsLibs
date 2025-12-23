#pragma once

#include <memory>

#include "common/defs.h"
#include "common/error.h"

#include "dns/proxy/dnsproxy_events.h"
#include "dns/proxy/dnsproxy_settings.h"

namespace ag::dns {

/**
 * DNS proxy module encapsulates DNS messages processing.
 * It parses, filters, communicates with a DNS resolver and generates answer to a client.
 */
class DnsProxy {
public:
    using DnsProxyInitResult = std::pair<bool, Error<DnsProxyInitError>>;

    DnsProxy();
    ~DnsProxy();

    DnsProxy(const DnsProxy &) = delete;
    DnsProxy(DnsProxy &&) = delete;
    DnsProxy &operator=(const DnsProxy &) = delete;
    DnsProxy &operator=(DnsProxy &&) = delete;

    /**
     * @brief Initialize the DNS proxy
     *
     * @param settings proxy settings (see `DnsProxySettings`)
     * @param events proxy events (see `DnsProxyEvents`)
     * @return {true, opt_warning_description} or {false, error_description}
     */
    [[nodiscard]] DnsProxyInitResult init(DnsProxySettings settings, DnsProxyEvents events);

    /**
     * @brief Deinitialize the DNS proxy
     */
    void deinit();

    /**
     * @brief Reapply DNS proxy settings with optional filter reloading
     *
     * @param settings New DNS proxy settings to apply
     * @param reapply_filters If true, DNS filters will be reloaded from settings.
     *                       If false, existing filters are preserved (fast update).
     * @return {true, opt_warning_description} or {false, error_description}
     * 
     */
    [[nodiscard]] DnsProxyInitResult reapply_settings(DnsProxySettings settings, bool reapply_filters);

    /**
     * @brief Get the DNS proxy settings
     * @return Current settings
     */
    [[nodiscard]] const DnsProxySettings &get_settings() const;

    /**
     * @brief Handle a DNS message
     *
     * @param message message from client
     * @param info (optional) additional information about the message in case it is being forwarded
     * @return A blocked DNS message in case of the message was blocked.
     *         A DNS resolver response in case of the message was passed.
     *         An empty buffer in case of error. This implies that no response
     *         should be sent to the requestor over the network.
     */
    coro::Task<Uint8Vector> handle_message(Uint8View message, const DnsMessageInfo *info);

    /**
     * Synchronous interface for @see `handle_message`
     */
    Uint8Vector handle_message_sync(Uint8View message, const DnsMessageInfo *info);

    /**
     * @brief Return the DNS proxy library version
     *
     * The caller does not take ownership of the returned string.
     */
    static const char *version();

private:
    struct Impl;
    std::unique_ptr<Impl> m_pimpl;

    DnsProxyInitResult reapply_settings_internal(DnsProxySettings settings, bool reapply_filters);
    coro::Task<Uint8Vector> handle_message_internal(Uint8View message, const DnsMessageInfo *info);

    friend class UdpListener;
    friend class TcpDnsConnection;
};

} // namespace ag::dns
