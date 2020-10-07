#pragma once

#include <chrono>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>
#include <ldns/packet.h>
#include <ag_defs.h>
#include <ag_net_consts.h>
#include <ag_net_utils.h>
#include <certificate_verifier.h>

namespace ag {

class upstream;

using upstream_ptr = std::unique_ptr<upstream>;
using ldns_pkt_ptr = std::unique_ptr<ldns_pkt, ag::ftor<&ldns_pkt_free>>;
using ldns_buffer_ptr = std::unique_ptr<ldns_buffer, ag::ftor<&ldns_buffer_free>>;

/**
 * Upstream factory configuration
 */
struct upstream_factory_config {
    const certificate_verifier *cert_verifier = nullptr;
    bool ipv6_available = true;
};

/**
 * Options for upstream
 */
struct upstream_options {
    /**
     * Server address, one of the following kinds:
     *     8.8.8.8:53 -- plain DNS
     *     tcp://8.8.8.8:53 -- plain DNS over TCP
     *     tls://1.1.1.1 -- DNS-over-TLS
     *     https://dns.adguard.com/dns-query -- DNS-over-HTTPS
     *     sdns://... -- DNS stamp (see https://dnscrypt.info/stamps-specifications)
     *     quic://dns.adguard.com:784 -- DNS-over-QUIC
     */
    std::string address;

    /** List of plain DNS servers to be used to resolve the hostname in upstreams's address. */
    std::vector<std::string> bootstrap;

    /** Upstream timeout. 0 means "default". */
    std::chrono::milliseconds timeout;

    /** Upstream's IP address. If specified, the bootstrapper is NOT used */
    ip_address_variant resolved_server_ip;

    /** User-provided ID for this upstream */
    int32_t id;
};

/**
 * Upstream is interface for handling DNS requests to upstream servers
 */
class upstream {
public:
    static constexpr std::chrono::milliseconds DEFAULT_TIMEOUT{5000};

    struct exchange_result {
        ldns_pkt_ptr packet;
        err_string error;
    };

    upstream(upstream_options opts, const upstream_factory_config &config) : m_options(std::move(opts)), m_config(config) {
        m_rtt.val = std::chrono::milliseconds::zero();
        if (!this->m_options.timeout.count()) {
            this->m_options.timeout = DEFAULT_TIMEOUT;
        }
    }

    virtual ~upstream() = default;

    /**
     * Initialize upstream
     * @return non-nullopt string in case of error
     */
    virtual err_string init() = 0;

    /**
     * Do DNS request
     * @param request DNS request packet
     * @return DNS response packet or an error
     */
    virtual exchange_result exchange(ldns_pkt *request) = 0;

    const upstream_options &options() const { return m_options; }

    const upstream_factory_config &config() const { return m_config; }

    const std::chrono::milliseconds rtt() {
        std::lock_guard<std::mutex> lk(m_rtt.mtx);
        return m_rtt.val;
    }

    /**
     * Update RTT
     * @param elapsed spent time in exchange()
     */
    void adjust_rtt(std::chrono::milliseconds elapsed) {
        std::lock_guard<std::mutex> lk(m_rtt.mtx);
        m_rtt.val = (m_rtt.val + elapsed) / 2;
    }

protected:
    /** Upstream options */
    upstream_options m_options;
    /** Upstream factory configuration */
    upstream_factory_config m_config;
    /** RTT + mutex */
    with_mtx<std::chrono::milliseconds> m_rtt;
};

/**
 * Upstream factory entity which produces upstreams
 */
class upstream_factory {
public:
    struct create_result {
        upstream_ptr upstream; // created upstream in case of success
        err_string error; // non-nullopt in case of error
    };

    explicit upstream_factory(upstream_factory_config cfg);
    ~upstream_factory();

    /**
     * Create an upstream
     * @param opts upstream settings
     * @return Creation result
     */
    create_result create_upstream(const upstream_options &opts) const;

    struct impl;
private:
    std::unique_ptr<impl> factory;
};

} // namespace ag
