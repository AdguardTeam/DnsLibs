#pragma once

#include "dns/net/aio_socket.h"
#include "dns/upstream/upstream.h"
#include "system_resolver.h"

#include <ldns/ldns.h>
#include <string_view>

namespace ag::dns {

/**
 * The SystemUpstream class is used for resolving DNS queries using the system resolver.
 * It supports specifying a network interface for the DNS resolution.
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
    ~SystemUpstream() override = default;

private:
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

    Logger m_log; ///< The logger for this upstream.
    std::unique_ptr<SystemResolver> m_resolver; ///< The system resolver used by this upstream.
    std::string m_interface; ///< The network interface used by this upstream.
};

} // namespace ag::dns

