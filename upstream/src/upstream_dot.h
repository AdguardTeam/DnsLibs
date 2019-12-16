#pragma once

#include <utility>
#include <upstream.h>
#include <event2/event.h>
#include <ldns/net.h>
#include "dns_framed.h"
#include "bootstrapper.h"

namespace ag {

class dns_over_tls;

/**
 * Pool of TLS connections
 */
class tls_pool : public dns_framed_pool {
public:
    /**
     * Create TLS pool
     * @param loop Event loop
     * @param upstream Parent upstream
     * @param bootstrapper Bootstrapper (used to resolve original address)
     */
    tls_pool(event_loop_ptr loop, dns_over_tls *upstream, bootstrapper_ptr &&bootstrapper)
            : dns_framed_pool(std::move(loop)), m_upstream(upstream), m_bootstrapper(std::move(bootstrapper)) {
    }

    get_result get() override;

    /**
     * @return Bootstrapper for server address
     */
    const ag::bootstrapper *bootstrapper();
private:
    /** Parent upstream */
    dns_over_tls *m_upstream = nullptr;
    /** Bootstrapper for server address */
    bootstrapper_ptr m_bootstrapper;

    get_result create();
};

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
    dns_over_tls(const ag::upstream::options &opts, const ag::upstream_factory::config &config);

    ~dns_over_tls() override = default;

    exchange_result exchange(ldns_pkt *request_pkt) override;

private:
    static int ssl_verify_callback(int ok, X509_STORE_CTX *store_ctx);
    friend class tls_pool; // to set private callback for verification

    logger m_log = create_logger("DOT upstream");
    /** TLS connection pool */
    tls_pool m_pool;
    /** Certificate verifier */
    const certificate_verifier *m_verifier = nullptr;
    /** DNS server name */
    std::string m_server_name;
};

} // namespace ag
