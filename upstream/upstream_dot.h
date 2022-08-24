#pragma once

#include <utility>
#include <event2/event.h>
#include <ldns/net.h>

#include "dns/net/tls_session_cache.h"
#include "dns/upstream/upstream.h"

#include "dns_framed.h"
#include "dns/upstream/bootstrapper.h"

namespace ag::dns {

class DotConnection;

/**
 * DNS-over-TLS upstream
 */
class DotUpstream : public Upstream {
public:
    /** Default port for DoT */
    static constexpr std::string_view SCHEME = "tls://";

    /**
     * Create DNS-over-TLS upstream
     * @param opts Upstream settings
     * @param config Factory configuration
     */
    DotUpstream(const UpstreamOptions &opts, const UpstreamFactoryConfig &config);

    ~DotUpstream() override;

private:
    Error<InitError> init() override;
    coro::Task<ExchangeResult> exchange(ldns_pkt *request, const DnsMessageInfo *info = nullptr) override;

    Logger m_log;
    /** TLS connection pool */
    ConnectionPoolPtr m_pool;
    /** DNS server name */
    std::string m_server_name;
    /** TLS sessions cache */
    TlsSessionCache m_tls_session_cache;
    /** Bootstrapper */
    BootstrapperPtr m_bootstrapper;

    friend class DotConnection;
};

} // namespace ag::dns
