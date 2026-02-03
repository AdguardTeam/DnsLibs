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

    enum ReapplyOptions : uint8_t {
        RO_NONE     = 0,      ///< No changes, no-op
        RO_SETTINGS = 1 << 0, ///< Reload all DNS settings except listeners and filter_params
        RO_FILTERS  = 1 << 1, ///< Reload filter parameters (filter_params)
    };

    friend inline ReapplyOptions operator|(ReapplyOptions l, ReapplyOptions r) {
        return ReapplyOptions((uint8_t)l | (uint8_t)r);
    }

    friend inline ReapplyOptions operator&(ReapplyOptions l, ReapplyOptions r) {
        return ReapplyOptions((uint8_t)l & (uint8_t)r);
    }

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
     * @brief Reapply DNS proxy settings with selective reloading
     *
     * This method allows updating DNS proxy configuration without full reinitialization.
     * You can selectively reload different parts of the configuration using ReapplyOptions flags.
     *
     * @param settings New DNS proxy settings to apply
     * @param reapply_options Bitwise OR combination of ReapplyOptions flags
     * @return {true, opt_warning_description} or {false, error_description}
     */
    [[nodiscard]] DnsProxyInitResult reapply_settings(DnsProxySettings settings, ReapplyOptions reapply_options);

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
     * @brief Check if a DNS message's domain matches `fallback_domains`
     *
     * This method parses `message` as a DNS packet and checks whether its question name matches
     * the configured `fallback_domains` patterns.
     *
     * @param message message from client
     * @return true if the question name matches `fallback_domains`, false otherwise
     */
    [[nodiscard]] bool match_fallback_domains(Uint8View message) const;

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

    DnsProxyInitResult reapply_settings_internal(DnsProxySettings settings, ReapplyOptions reapply_options);
    coro::Task<Uint8Vector> handle_message_internal(Uint8View message, const DnsMessageInfo *info);
    bool match_fallback_domains_internal(Uint8View message) const;

    friend class UdpListener;
    friend class TcpDnsConnection;
};

} // namespace ag::dns
