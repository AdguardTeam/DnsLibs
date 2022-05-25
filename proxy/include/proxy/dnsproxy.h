#pragma once

#include <memory>
#include "common/defs.h"
#include "proxy/dnsproxy_settings.h"
#include "proxy/dnsproxy_events.h"

namespace ag {

/**
 * DNS proxy module is intended to incapsulate DNS messages processing.
 * It parses, filters, communicates with a DNS resolver and generates answer to a client.
 */
class DnsProxy {
public:
    static const ErrString LISTENER_ERROR;

    DnsProxy();
    ~DnsProxy();

    DnsProxy(const DnsProxy &) = delete;
    DnsProxy(DnsProxy &&) = delete;
    DnsProxy &operator=(const DnsProxy &) = delete;
    DnsProxy &operator=(DnsProxy &&) = delete;

    /**
     * @brief Initialize the DNS proxy
     *
     * @param settings proxy settings (see `dnsproxy_settings`)
     * @param events proxy events (see `dnsproxy_events`)
     * @return {true, opt_warning_description} or {false, error_description}
     */
    std::pair<bool, ErrString> init(DnsProxySettings settings, DnsProxyEvents events);

    /**
     * @brief Deinitialize the DNS proxy
     */
    void deinit();

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
    Uint8Vector handle_message(Uint8View message, const DnsMessageInfo *info);

    /**
     * @brief Return the DNS proxy library version
     *
     * The caller does not take ownership of the returned string.
     */
    static const char *version();

private:
    struct Impl;
    std::unique_ptr<Impl> m_pimpl;
};

} // namespace ag