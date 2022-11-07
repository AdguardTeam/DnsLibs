#pragma once

#include <chrono>
#include <event2/event.h>
#include <event2/util.h>
#include <memory>
#include <optional>
#include <string>
#include <variant>
#include <vector>

#include "common/defs.h"
#include "common/error.h"
#include "common/net_utils.h"
#include "common/logger.h"
#include "common/route_resolver.h"
#include "dns/common/event_loop.h"
#include "dns/net/outbound_proxy_settings.h"
#include "dns/net/certificate_verifier.h"
#include "dns/net/tls_session_cache.h"


namespace ag {
namespace dns {

class Socket;

class OutboundProxy;

enum class SocketError {
    AE_SOCK_ERROR,
    AE_ALREADY_CONNECTED,
    AE_PREPARE_ERROR,
    AE_SET_TIMEOUT_ERROR,
    AE_TIMED_OUT,
    AE_CONNECTION_REFUSED,
    AE_CONNECTION_ID_NOT_FOUND,
    AE_DUPLICATE_ID,
    AE_INVALID_CONN_STATE,
    AE_UNEXPECTED_DATA,
    AE_UDP_ASSOCIATION_TERMINATED,
    AE_UDP_ASSOCIATION_NOT_FOUND,
    AE_BAD_PROXY_REPLY,
    AE_TLS_ERROR,
    AE_OUTBOUND_PROXY_ERROR,
    AE_IN_PROGRESS,
};

class SocketFactory {
public:
    using SocketPtr = std::unique_ptr<Socket>;

    struct ProxyBootstrapper { // NOLINT(cppcoreguidelines-special-member-functions,hicpp-special-member-functions)
        /**
         * `nullopt` argument means the resolve failure
         */
        using Callback = std::function<void(std::optional<SocketAddress>)>;

        virtual ~ProxyBootstrapper() = default;

        /**
         * Resolve the hostname
         * @param host The name to resolve
         * @param bootstrap The bootstrap servers
         * @param timeout The resolve timeout
         * @param outbound_interface (optional) The network interface to route traffic through
         * @param callback The result handling procedure
         * @return true if started successfully, false otherwise
         */
        virtual bool resolve(std::string_view host, const std::vector<std::string> &bootstrap, Millis timeout,
                IfIdVariant outbound_interface, Callback callback) = 0;
    };

    struct Parameters {
        EventLoop &loop;
        struct {
            const OutboundProxySettings *settings = nullptr;
            std::unique_ptr<ProxyBootstrapper> bootstrapper;
        } oproxy;
        std::unique_ptr<CertificateVerifier> verifier;
        bool enable_route_resolver = true;
    };

    struct SocketParameters {
        /** Socket protocol */
        utils::TransportProtocol proto;
        /** (Optional) name or index of the network interface to route traffic through */
        IfIdVariant outbound_interface;
        /** If set to true, the socket will be connected directly to the peer */
        bool ignore_proxy_settings;
    };

    struct SecureSocketParameters {
        /** TLS session cache */
        TlsSessionCache *session_cache = nullptr;
        /** Target server name */
        std::string server_name;
        /** Application layer protocols */
        std::vector<std::string> alpn;
    };

    explicit SocketFactory(Parameters parameters);

    ~SocketFactory();

    SocketFactory(SocketFactory &&) = delete;

    SocketFactory &operator=(SocketFactory &&) = delete;

    SocketFactory(const SocketFactory &) = delete;

    SocketFactory &operator=(const SocketFactory &) = delete;

    /**
     * Deinitialize the factory
     */
    void deinit();

    /**
     * Create a socket basing on the factory and provided parameters
     * @param parameters the socket parameters
     * @return the socket
     */
    [[nodiscard]] SocketPtr make_socket(SocketParameters parameters) const;

    /**
     * Create a socket that encrypts the data sent through it
     * @param parameters the socket parameters
     * @param secure_parameters the security parameters
     * @return the socket
     */
    [[nodiscard]] SocketPtr make_secured_socket(SocketParameters parameters,
                                                SecureSocketParameters secure_parameters) const;

    /**
     * Prepare an externally created descriptor in the same way as `make_socket` does
     * @param fd the descriptor to be prepared
     * @param peer the destination peer address
     * @param outbound_interface name or index of the network interface to route traffic through
     * @return some error if failed
     */
    [[nodiscard]] ErrString prepare_fd(evutil_socket_t fd,
                                       const SocketAddress &peer, const IfIdVariant &outbound_interface) const;

    /**
     * Get outbound proxy settings
     * @return null if the proxy is not configured, non-null otherwise
     */
    [[nodiscard]] const OutboundProxySettings *get_outbound_proxy_settings() const;

    /**
     * Get the certificate verifier
     */
    [[nodiscard]] const CertificateVerifier *get_certificate_verifier() const;

    /**
     * Check whether a connection should be routed through proxy
     * @param proto the connection protocol
     * @return true if it should be proxied, false otherwise
     */
    [[nodiscard]] bool should_route_through_proxy(utils::TransportProtocol proto) const;

    /**
     * Check whether the proxy server is available
     */
    [[nodiscard]] bool is_proxy_available() const;

    /**
     * Register a successful connection to the proxy server
     */
    void on_successful_proxy_connection();

    enum ProxyConectionFailedResult {
        /// Close a connection
        SFPCFR_CLOSE_CONNECTION,
        /// Re-route a connection directly to the target
        SFPCFR_RETRY_DIRECTLY,
    };

    /**
     * Register the proxy server connection failure
     * @param err error code, if some
     */
    [[nodiscard]] ProxyConectionFailedResult on_proxy_connection_failed(Error<SocketError> err);

    struct ResetBypassedProxyConnectionsSubscriber {
        void (*func)(void *arg);

        void *arg;
    };

    /**
     * Subscribe to postponed event a handler of which should reset the connections which were
     * re-routed directly to the host after `SFPCFR_RETRY_DIRECTLY`
     * @param subscriber the subscriber
     * @return subscriber ID
     */
    uint32_t subscribe_to_reset_bypassed_proxy_connections_event(ResetBypassedProxyConnectionsSubscriber subscriber);

    /**
     * Unsubscribe from the reset event
     * @param id the subscriber ID
     */
    void unsubscribe_from_reset_bypassed_proxy_connections_event(uint32_t id);

private:
    struct OutboundProxyState;

    Parameters m_parameters;
    RouteResolverPtr m_router;
    std::unique_ptr<OutboundProxyState> m_proxy;

    [[nodiscard]] SocketPtr make_direct_socket(SocketParameters parameters) const;

    [[nodiscard]] SocketPtr make_secured_socket(SocketPtr underlying_socket,
                                                SecureSocketParameters secure_parameters) const;

    static ErrString on_prepare_fd(void *arg, evutil_socket_t fd,
                                   const SocketAddress &peer, const IfIdVariant &outbound_interface);

    [[nodiscard]] OutboundProxy *make_proxy() const;

    [[nodiscard]] OutboundProxy *make_fallback_proxy() const;

    static SocketFactory::SocketPtr on_make_proxy_socket(void *arg, utils::TransportProtocol proto,
                                                         std::optional<SecureSocketParameters> secure_parameters);

    static void on_reset_bypassed_proxy_connections(void *arg);
};

class Socket {
public:

    struct Callbacks {
        /** Raised after successful connection */
        void (*on_connected)(void *arg);

        /** Raised after a data chunk has been received */
        void (*on_read)(void *arg, Uint8View data);

        /**
         * Raised after the connection is closed
         * @param error none if closed gracefully
         */
        void (*on_close)(void *arg, Error<SocketError> error);

        /** User context for the callbacks */
        void *arg;
    };

    struct ConnectParameters {
        /** Event loop for operation */
        EventLoop *loop = nullptr;
        /** Address on the peer to connect to */
        const SocketAddress &peer;
        /** Set of the socket callbacks */
        Callbacks callbacks = {};
        /** Operation time out value */
        std::optional<Micros> timeout;
    };

    virtual ~Socket() = default;

    Socket(Socket &&) = default;

    Socket &operator=(Socket &&) = default;

    Socket(const Socket &) = delete;

    Socket &operator=(const Socket &) = delete;

    /**
     * Get the socket protocol
     */
    [[nodiscard]] utils::TransportProtocol get_protocol() const;

    /**
     * Get underlying file descriptor
     */
    [[nodiscard]] virtual std::optional<evutil_socket_t> get_fd() const = 0;

    /**
     * Get the peer address
     */
    [[nodiscard]] SocketAddress get_peer() const;

    /**
     * Initiate connection to the peer
     * @param params connection parameters
     * @return some error if failed
     */
    [[nodiscard]] virtual Error<SocketError> connect(ConnectParameters params) = 0;

    /**
     * Send data to the peer
     * @param data the data
     * @return some error if failed
     */
    [[nodiscard]] virtual Error<SocketError> send(Uint8View data) = 0;

    /**
     * Send DNS packet to the peer
     * @param data the packet
     * @return some error if failed
     */
    [[nodiscard]] virtual Error<SocketError> send_dns_packet(Uint8View data) = 0;

    /**
     * Set operation time out
     * @param timeout the time out value
     * @return true if successful
     */
    virtual bool set_timeout(Micros timeout) = 0;

    /**
     * Update socket callbacks. May be used to turn on/off the read events
     * @param cbx the callbacks
     * @return some error if failed
     */
    [[nodiscard]] virtual Error<SocketError> set_callbacks(Callbacks cbx) = 0;

protected:
    friend class SocketFactory;

    struct PrepareFdCallback {
        /** Raised after the descriptor creation */
        ErrString (*func)(void *arg, evutil_socket_t fd,
                          const SocketAddress &peer, const IfIdVariant &outbound_interface);

        /** User context for the callback */
        void *arg;
    };

    Logger m_log;
    size_t m_id = 0;
    SocketFactory::SocketParameters m_parameters = {};
    PrepareFdCallback m_prepare_fd = {};

    Socket(const std::string &logger_name,
           SocketFactory::SocketParameters parameters, PrepareFdCallback prepare_fd);
};

} // namespace dns

template<>
struct ErrorCodeToString<dns::SocketError> {
    std::string operator()(dns::SocketError e) {
        switch (e) {
        case decltype(e)::AE_SOCK_ERROR: return "Sockets error";
        case decltype(e)::AE_ALREADY_CONNECTED: return "Socket slready connected";
        case decltype(e)::AE_PREPARE_ERROR: return "Error preparing socket";
        case decltype(e)::AE_SET_TIMEOUT_ERROR: return "Failed to set timeout";
        case decltype(e)::AE_TIMED_OUT: return "Timed out";
        case decltype(e)::AE_CONNECTION_REFUSED: return "Connection refused";
        case decltype(e)::AE_CONNECTION_ID_NOT_FOUND: return "Non-existent connection ID";
        case decltype(e)::AE_DUPLICATE_ID: return "Duplicate connection ID";
        case decltype(e)::AE_INVALID_CONN_STATE: return "Invalid connection state";
        case decltype(e)::AE_UNEXPECTED_DATA: return "Unexpected data";
        case decltype(e)::AE_UDP_ASSOCIATION_TERMINATED: return "UDP association terminated";
        case decltype(e)::AE_UDP_ASSOCIATION_NOT_FOUND: return "UDP association not found";
        case decltype(e)::AE_BAD_PROXY_REPLY: return "Bad proxy reply";
        case decltype(e)::AE_TLS_ERROR: return "TLS error";
        case decltype(e)::AE_OUTBOUND_PROXY_ERROR: return "Proxy error";
        case decltype(e)::AE_IN_PROGRESS: return "Async operation in progress";
        default: return AG_FMT("Unknown error: {}", (int)e);
        }
    }
};

template<>
struct ErrorCodeToString<uv_errno_t> {
    std::string operator()(uv_errno_t e) {
        const char *msg = uv_strerror(int(e));
        if (!msg) {
            return AG_FMT("Unknown error: {}", int(e));
        }
        return msg;
    }
};

} // namespace ag
