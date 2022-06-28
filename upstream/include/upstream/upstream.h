#pragma once

#include <chrono>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>
#include <ldns/packet.h>
#include "common/defs.h"
#include "common/net_consts.h"
#include "common/net_utils.h"
#include "common/dns_utils.h"
#include "net/certificate_verifier.h"
#include "net/socket.h"
#include "net/tls_session_cache.h"

namespace ag {

class Upstream;

using UpstreamPtr = std::unique_ptr<Upstream>;
using ldns_pkt_ptr = UniquePtr<ldns_pkt, &ldns_pkt_free>;
using ldns_buffer_ptr = UniquePtr<ldns_buffer, &ldns_buffer_free>;

static constexpr std::string_view TIMEOUT_STR = "Request timed out";

/**
 * Upstream factory configuration
 */
struct UpstreamFactoryConfig {
    SocketFactory *socket_factory = nullptr;
    bool ipv6_available = true;
};

/**
 * Options for upstream
 */
struct UpstreamOptions {
    /**
     * Server address, one of the following kinds:
     *     8.8.8.8:53 -- plain DNS
     *     tcp://8.8.8.8:53 -- plain DNS over TCP
     *     tls://1.1.1.1 -- DNS-over-TLS
     *     https://dns.adguard.com/dns-query -- DNS-over-HTTPS
     *     sdns://... -- DNS stamp (see https://dnscrypt.info/stamps-specifications)
     *     quic://dns.adguard.com:853 -- DNS-over-QUIC
     */
    std::string address;

    /** List of plain DNS servers to be used to resolve the hostname in upstreams's address. */
    std::vector<std::string> bootstrap;

    /** Upstream timeout. 0 means "default". */
    Millis timeout;

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
class Upstream {
public:
    static constexpr Millis DEFAULT_TIMEOUT{5000};

    struct ExchangeResult {
        ldns_pkt_ptr packet;
        // @todo: pass an error code to not rely on an error message in the DNS forwarder
        ErrString error;
    };

    Upstream(UpstreamOptions opts, const UpstreamFactoryConfig &config)
        : m_options(std::move(opts))
        , m_config(config)
    {
        m_rtt = Millis::zero();
        if (!m_options.timeout.count()) {
            m_options.timeout = DEFAULT_TIMEOUT;
        }
    }

    virtual ~Upstream() = default;

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
    virtual ExchangeResult exchange(ldns_pkt *request, const ag::DnsMessageInfo *info = nullptr) = 0;

    [[nodiscard]] const UpstreamOptions &options() const { return m_options; }

    [[nodiscard]] const UpstreamFactoryConfig &config() const { return m_config; }

    /**
     * Helper function for easier socket creation
     */
    [[nodiscard]] SocketFactory::SocketPtr make_socket(utils::TransportProtocol proto) const {
        return m_config.socket_factory->make_socket(
                { proto, m_options.outbound_interface, m_options.ignore_proxy_settings });
    }
    [[nodiscard]] SocketFactory::SocketPtr make_secured_socket(utils::TransportProtocol proto,
                                                               SocketFactory::SecureSocketParameters secure_socket_parameters) const {
        return m_config.socket_factory->make_secured_socket(
                { proto, m_options.outbound_interface, m_options.ignore_proxy_settings },
                std::move(secure_socket_parameters));
    }

    Millis rtt() {
        std::lock_guard<std::mutex> lk(m_rtt_guard);
        return m_rtt;
    }

    /**
     * Update RTT
     * @param elapsed spent time in exchange()
     */
    void adjust_rtt(Millis elapsed) {
        std::lock_guard<std::mutex> lk(m_rtt_guard);
        m_rtt = (m_rtt + elapsed) / 2;
    }

protected:
    /** Upstream options */
    UpstreamOptions m_options;
    /** Upstream factory configuration */
    UpstreamFactoryConfig m_config;
    /** RTT + mutex */
    Millis m_rtt;
    std::mutex m_rtt_guard;
};

/**
 * Upstream factory entity which produces upstreams
 */
class UpstreamFactory {
public:
    struct CreateResult {
        UpstreamPtr upstream; // created upstream in case of success
        ErrString error; // non-nullopt in case of error
    };

    explicit UpstreamFactory(UpstreamFactoryConfig cfg);
    ~UpstreamFactory();

    /**
     * Create an upstream
     * @param opts upstream settings
     * @return Creation result
     */
    CreateResult create_upstream(const UpstreamOptions &opts) const;

    struct Impl;
private:
    std::unique_ptr<Impl> m_factory;
};

} // namespace ag
