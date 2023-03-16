#pragma once

#include <algorithm>
#include <chrono>
#include <memory>
#include <numeric>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>
#include <ldns/packet.h>

#include "common/coro.h"
#include "common/defs.h"
#include "common/net_utils.h"
#include "dns/common/dns_defs.h"
#include "dns/common/net_consts.h"
#include "dns/common/dns_utils.h"
#include "dns/net/certificate_verifier.h"
#include "dns/net/socket.h"
#include "dns/net/tls_session_cache.h"

namespace ag {
namespace dns {

class Upstream;

using UpstreamPtr = std::shared_ptr<Upstream>;
using ldns_pkt_ptr = UniquePtr<ldns_pkt, &ldns_pkt_free>; // NOLINT(readability-identifier-naming)
using ldns_buffer_ptr = UniquePtr<ldns_buffer, &ldns_buffer_free>; // NOLINT(readability-identifier-naming)

/**
 * Upstream factory configuration
 */
struct UpstreamFactoryConfig {
    EventLoop &loop;
    SocketFactory *socket_factory = nullptr;
    bool ipv6_available = true;
    bool enable_http3 = false; /**< Enable opportunistic use of HTTP/3 for applicable upstream types */
    Millis timeout{};
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

    /**
     * List of the DNS server URLs to be used to resolve a hostname in the upstream address.
     * The URLs MUST contain the resolved server addresses, not hostnames.
     * E.g. `https://94.140.14.14` is correct, while `dns.adguard.com:53` is not.
     */
    std::vector<std::string> bootstrap;

    /** Upstream's IP address. If specified, the bootstrapper is NOT used */
    IpAddress resolved_server_ip;

    /** User-provided ID for this upstream */
    int32_t id;

    /** (Optional) name or index of the network interface to route traffic through */
    IfIdVariant outbound_interface;

    /**
     * (Optional) List of upstreams base64 encoded SPKI fingerprints to verify. If at least one of them is matched in the
     * certificate chain, the verification will be successful
     */
    std::vector<std::string> fingerprints;

    /** If set to true, an outbound proxy won't be used for the upstream's network connections */
    bool ignore_proxy_settings; // @todo: expose this flag in the public API if it's needed
};

/**
 * Upstream is interface for handling DNS requests to upstream servers
 */
class Upstream : public std::enable_shared_from_this<Upstream> {
public:
    enum class InitError {
        AE_EMPTY_SERVER_NAME,
        AE_EMPTY_BOOTSTRAP,
        AE_BOOTSTRAPPER_INIT_FAILED,
        AE_INVALID_ADDRESS,
        AE_SSL_CONTEXT_INIT_FAILED,
        AE_CURL_HEADERS_INIT_FAILED,
        AE_CURL_POOL_INIT_FAILED,
    };

    Upstream(UpstreamOptions opts, UpstreamFactoryConfig config)
            : m_options(std::move(opts)), m_config(std::move(config)) {}

    virtual ~Upstream() = default;

    /**
     * Initialize upstream
     * @return Error in case of error, nullptr otherwise
     */
    virtual Error<InitError> init() = 0;

    using ExchangeResult = Result<ldns_pkt_ptr, DnsError>;

    /**
     * Do DNS exchange, considering that `request` may be a forwarded request.
     * @param request DNS request message
     * @param info (optional) out of band info about the forwarded DNS request message
     * @return DNS response message or an error
     */
    virtual coro::Task<ExchangeResult> exchange(const ldns_pkt *request, const DnsMessageInfo *info = nullptr) = 0;

    [[nodiscard]] const UpstreamOptions &options() const { return m_options; }

    [[nodiscard]] const UpstreamFactoryConfig &config() const { return m_config; }

    /**
     * Helper function for easier socket creation
     */
    [[nodiscard]] SocketFactory::SocketPtr make_socket(utils::TransportProtocol proto) const {
        return m_config.socket_factory->make_socket(
                {proto, m_options.outbound_interface, m_options.ignore_proxy_settings});
    }

    [[nodiscard]] SocketFactory::SocketPtr make_secured_socket(utils::TransportProtocol proto,
                                                               SocketFactory::SecureSocketParameters secure_socket_parameters) const {
        return m_config.socket_factory->make_secured_socket(
                {proto, m_options.outbound_interface, m_options.ignore_proxy_settings},
                std::move(secure_socket_parameters));
    }

    /**
     * Return the round trip time estimate for this upstream.
     * Return std::nullopt if no data points have been gathered yet.
     */
    std::optional<Millis> rtt_estimate() const {
        return m_rtt_estimate ? std::make_optional(m_rtt_estimate->get()) : std::nullopt;
    }

    /**
     * Update the round trip time estimate with a new measured value.
     */
    void update_rtt_estimate(Millis elapsed) {
        if (!m_rtt_estimate) {
            m_rtt_estimate.emplace(RTT_AVG_INIT);
        }
        m_rtt_estimate->update(elapsed); // NOLINT(bugprone-unchecked-optional-access)
    }

protected:
    /** Keeps the average of the last N values of type T. */
    template <typename T, size_t N>
    class RunningAverage {
    private:
        T m_vals[N]{};
        size_t m_idx = 0;

    public:
        explicit RunningAverage(T init) {
            set(init);
        }

        void update(T new_val) {
            m_vals[m_idx] = new_val; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
            m_idx = (m_idx + 1) % N;
        }

        [[nodiscard]] T get() const {
            return std::accumulate(std::begin(m_vals), std::end(m_vals), T{}) / N;
        }

        void set(T value) {
            std::fill(std::begin(m_vals), std::end(m_vals), value);
        }
    };

    /** Upstream options */
    UpstreamOptions m_options;
    /** Upstream factory configuration */
    UpstreamFactoryConfig m_config;
    /** RTT estimate */
    static constexpr size_t RTT_AVG_WINDOW_SIZE = 10;
    static constexpr Millis RTT_AVG_INIT{50};
    std::optional<RunningAverage<Millis, RTT_AVG_WINDOW_SIZE>> m_rtt_estimate;
};

/**
 * Upstream factory entity which produces upstreams
 */
class UpstreamFactory {
public:
    static constexpr auto DEFAULT_TIMEOUT = Millis{5000};

    enum class UpstreamCreateError {
        AE_INVALID_URL,
        AE_INVALID_STAMP,
        AE_INVALID_FINGERPRINT,
        AE_INIT_FAILED,
    };
    using CreateResult = Result<UpstreamPtr, UpstreamCreateError>;

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

} // namespace dns

// clang format off
template<>
struct ErrorCodeToString<dns::UpstreamFactory::UpstreamCreateError> {
    std::string operator()(dns::UpstreamFactory::UpstreamCreateError e) {
        switch (e) {
        case decltype(e)::AE_INVALID_URL: return "Invalid URL";
        case decltype(e)::AE_INVALID_STAMP: return "Invalid DNS stamp";
        case decltype(e)::AE_INVALID_FINGERPRINT: return "Passed fingerprint is not valid";
        case decltype(e)::AE_INIT_FAILED: return "Error initializing upstream";
        }
    }
};

template<>
struct ErrorCodeToString<dns::Upstream::InitError> {
    std::string operator()(dns::Upstream::InitError e) {
        switch (e) {
        case decltype(e)::AE_EMPTY_SERVER_NAME: return "Server name is empty";
        case decltype(e)::AE_EMPTY_BOOTSTRAP: return "Bootstrap should not be empty when server IP address is not known";
        case decltype(e)::AE_BOOTSTRAPPER_INIT_FAILED: return "Failed to create bootstrapper";
        case decltype(e)::AE_INVALID_ADDRESS: return "Passed server address is not valid";
        case decltype(e)::AE_SSL_CONTEXT_INIT_FAILED: return "Failed to initialize SSL context";
        case decltype(e)::AE_CURL_HEADERS_INIT_FAILED: return "Failed to initialize CURL headers";
        case decltype(e)::AE_CURL_POOL_INIT_FAILED: return "Failed to initialize CURL connection pool";
        }
    }
};
// clang format on

} // namespace ag
