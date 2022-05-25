#pragma once

#include <utility>
#include "upstream/upstream.h"
#include <event2/event.h>
#include <ldns/net.h>
#include "dns_framed.h"
#include "bootstrapper.h"
#include "net/tls_session_cache.h"

namespace ag {

/**
 * DNS-over-TLS upstream
 */
class DotUpstream : public Upstream {
public:
    /** Default port for DoT */
    static constexpr auto DEFAULT_PORT = 853;
    static constexpr std::string_view SCHEME = "tls://";

    /**
     * Create DNS-over-TLS upstream
     * @param opts Upstream settings
     * @param config Factory configuration
     */
    DotUpstream(const UpstreamOptions &opts, const UpstreamFactoryConfig &config);

    ~DotUpstream() override;

private:
    ErrString init() override;
    ExchangeResult exchange(ldns_pkt *request_pkt, const DnsMessageInfo *info) override;

    class TlsPool;

    Logger m_log;
    /** TLS connection pool */
    std::unique_ptr<TlsPool> m_pool;
    /** DNS server name */
    std::string m_server_name;
    /** TLS sessions cache */
    TlsSessionCache m_tls_session_cache;
};

} // namespace ag
