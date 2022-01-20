#pragma once

#include <chrono>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>
#include <ldns/packet.h>
#include "common/defs.h"
#include <ag_net_consts.h>
#include "common/net_utils.h"
#include <ag_dns_utils.h>
#include <certificate_verifier.h>
#include <ag_socket.h>
#include <tls_session_cache.h>

namespace ag {

class upstream;

using upstream_ptr = std::unique_ptr<upstream>;
using ldns_pkt_ptr = UniquePtr<ldns_pkt, &ldns_pkt_free>;
using ldns_buffer_ptr = UniquePtr<ldns_buffer, &ldns_buffer_free>;

static constexpr std::string_view TIMEOUT_STR = "Request timed out";

/**
 * Upstream factory configuration
 */
struct upstream_factory_config {
    socket_factory *socket_factory = nullptr;
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
     *     quic://dns.adguard.com:8853 -- DNS-over-QUIC
     */
    std::string address;

    /** List of plain DNS servers to be used to resolve the hostname in upstreams's address. */
    std::vector<std::string> bootstrap;

    /** Upstream timeout. 0 means "default". */
    std::chrono::milliseconds timeout;

    /** Upstream's IP address. If specified, the bootstrapper is NOT used */
    IpAddress resolved_server_ip;

    /** User-provided ID for this upstream */
    int32_t id;

    /** (Optional) name or index of the network interface to route traffic through */
    IfIdVariant outbound_interface;

    /** If set to true, an outbound proxy won't be used for the upstream's network connections */
    bool ignore_proxy_settings; // @todo: expose this flag in the public API if it's needed
};

/**
 * Upstream is interface for handling DNS requests to upstream servers
 */
class upstream {
public:
    static constexpr std::chrono::milliseconds DEFAULT_TIMEOUT{5000};

    struct exchange_result {
        ldns_pkt_ptr packet;
        ErrString error;
    };

    upstream(upstream_options opts, const upstream_factory_config &config)
        : m_options(std::move(opts))
        , m_config(config)
    {
        m_rtt = std::chrono::milliseconds::zero();
        if (!this->m_options.timeout.count()) {
            this->m_options.timeout = DEFAULT_TIMEOUT;
        }
    }

    virtual ~upstream() = default;

    /**
     * Initialize upstream
     * @return non-nullopt string in case of error
     */
    virtual ErrString init() = 0;

    /**
     * Do DNS exchange, considering that `request` may be a forwarded request.
     * @param request DNS request message
     * @param info (optional) out of band info about the forwarded DNS request message
     * @return DNS response message or an error
     */
    virtual exchange_result exchange(ldns_pkt *request, const ag::dns_message_info *info = nullptr) = 0;

    [[nodiscard]] const upstream_options &options() const { return m_options; }

    [[nodiscard]] const upstream_factory_config &config() const { return m_config; }

    /**
     * Helper function for easier socket creation
     */
    [[nodiscard]] socket_factory::socket_ptr make_socket(utils::TransportProtocol proto) const {
        return m_config.socket_factory->make_socket(
                { proto, m_options.outbound_interface, m_options.ignore_proxy_settings });
    }
    [[nodiscard]] socket_factory::socket_ptr make_secured_socket(utils::TransportProtocol proto,
            socket_factory::secure_socket_parameters secure_socket_parameters) const {
        return m_config.socket_factory->make_secured_socket(
                { proto, m_options.outbound_interface, m_options.ignore_proxy_settings },
                std::move(secure_socket_parameters));
    }

    std::chrono::milliseconds rtt() {
        std::lock_guard<std::mutex> lk(m_rtt_guard);
        return m_rtt;
    }

    /**
     * Update RTT
     * @param elapsed spent time in exchange()
     */
    void adjust_rtt(std::chrono::milliseconds elapsed) {
        std::lock_guard<std::mutex> lk(m_rtt_guard);
        m_rtt = (m_rtt + elapsed) / 2;
    }

protected:
    /** Upstream options */
    upstream_options m_options;
    /** Upstream factory configuration */
    upstream_factory_config m_config;
    /** RTT + mutex */
    std::chrono::milliseconds m_rtt;
    std::mutex m_rtt_guard;
};

/**
 * Upstream factory entity which produces upstreams
 */
class upstream_factory {
public:
    struct create_result {
        upstream_ptr upstream; // created upstream in case of success
        ErrString error; // non-nullopt in case of error
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
