#pragma once

#include <utility>
#include <upstream.h>
#include <event2/event.h>
#include <ldns/net.h>
#include "dns_framed.h"
#include "bootstrapper.h"
#include <tls_session_cache.h>

namespace ag {

/**
 * DNS-over-TLS upstream
 */
class dns_over_tls : public upstream {
public:
    /** Default port for DoT */
    static constexpr auto DEFAULT_PORT = 853;
    static constexpr std::string_view SCHEME = "tls://";

    /**
     * Create DNS-over-TLS upstream
     * @param opts Upstream settings
     * @param config Factory configuration
     */
    dns_over_tls(const upstream_options &opts, const upstream_factory_config &config);

    ~dns_over_tls() override;

private:
    ErrString init() override;
    exchange_result exchange(ldns_pkt *request_pkt, const dns_message_info *info) override;

    class tls_pool;

    Logger m_log;
    /** TLS connection pool */
    std::unique_ptr<tls_pool> m_pool;
    /** DNS server name */
    std::string m_server_name;
    /** TLS sessions cache */
    tls_session_cache m_tls_session_cache;
};

} // namespace ag
