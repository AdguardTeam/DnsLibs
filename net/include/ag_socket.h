#pragma once


#include <optional>
#include <chrono>
#include <string>
#include <variant>
#include <memory>
#include <vector>
#include <event2/event.h>
#include <event2/util.h>
#include "common/defs.h"
#include "common/net_utils.h"
#include "common/logger.h"
#include "common/route_resolver.h"
#include <ag_outbound_proxy_settings.h>
#include <ag_event_loop.h>
#include <certificate_verifier.h>
#include <tls_session_cache.h>


namespace ag {

class socket;
class outbound_proxy;

class socket_factory {
public:
    using socket_ptr = std::unique_ptr<socket>;

    struct parameters {
        const outbound_proxy_settings *oproxy_settings = nullptr;
        std::unique_ptr<certificate_verifier> verifier;
    };

    struct socket_parameters {
        /** Socket protocol */
        utils::TransportProtocol proto;
        /** (Optional) name or index of the network interface to route traffic through */
        IfIdVariant outbound_interface;
        /** If set to true, the socket will be connected directly to the peer */
        bool ignore_proxy_settings;
    };

    struct secure_socket_parameters {
        /** TLS session cache */
        tls_session_cache *session_cache = nullptr;
        /** Target server name */
        std::string server_name;
        /** Application layer protocols */
        std::vector<std::string> alpn;
    };

    explicit socket_factory(parameters parameters);
    ~socket_factory();

    socket_factory(socket_factory &&) = delete;
    socket_factory &operator=(socket_factory &&) = delete;
    socket_factory(const socket_factory &) = delete;
    socket_factory &operator=(const socket_factory &) = delete;

    /**
     * Create a socket basing on the factory and provided parameters
     * @param parameters the socket parameters
     * @return the socket
     */
    [[nodiscard]] socket_ptr make_socket(socket_parameters parameters) const;

    /**
     * Create a socket that encrypts the data sent through it
     * @param parameters the socket parameters
     * @param secure_parameters the security parameters
     * @return the socket
     */
    [[nodiscard]] socket_ptr make_secured_socket(socket_parameters parameters,
            secure_socket_parameters secure_parameters) const;

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
    [[nodiscard]] const outbound_proxy_settings *get_outbound_proxy_settings() const;

    /**
     * Get the certificate verifier
     */
    [[nodiscard]] const certificate_verifier *get_certificate_verifier() const;

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

    enum proxy_connection_failed_result {
        /// Close a connection
        SFPCFR_CLOSE_CONNECTION,
        /// Re-route a connection directly to the target
        SFPCFR_RETRY_DIRECTLY,
    };

    /**
     * Register the proxy server connection failure
     * @param err error code, if some
     */
    [[nodiscard]] proxy_connection_failed_result on_proxy_connection_failed(std::optional<int> err);

    struct reset_bypassed_proxy_connections_subscriber {
        void (* func)(void *arg);
        void *arg;
    };

    /**
     * Subscribe to postponed event a handler of which should reset the connections which were
     * re-routed directly to the host after `SFPCFR_RETRY_DIRECTLY`
     * @param subscriber the subscriber
     * @return subscriber ID
     */
    uint32_t subscribe_to_reset_bypassed_proxy_connections_event(reset_bypassed_proxy_connections_subscriber subscriber);

    /**
     * Unsubscribe from the reset event
     * @param id the subscriber ID
     */
    void unsubscribe_from_reset_bypassed_proxy_connections_event(uint32_t id);

private:
    struct outbound_proxy_state;

    parameters parameters = {};
    RouteResolverPtr router;
    std::unique_ptr<outbound_proxy_state> proxy;

    [[nodiscard]] socket_ptr make_direct_socket(socket_parameters parameters) const;
    [[nodiscard]] socket_ptr make_secured_socket(socket_ptr underlying_socket,
            secure_socket_parameters secure_parameters) const;
    static ErrString on_prepare_fd(void *arg, evutil_socket_t fd,
                                   const SocketAddress &peer, const IfIdVariant &outbound_interface);
    [[nodiscard]] outbound_proxy *make_proxy() const;
    [[nodiscard]] outbound_proxy *make_fallback_proxy() const;
    static socket_factory::socket_ptr on_make_proxy_socket(void *arg, utils::TransportProtocol proto,
            std::optional<secure_socket_parameters> secure_parameters);
    static void on_reset_bypassed_proxy_connections(void *arg);
};

class socket {
public:
    struct error {
        /** Error code (either system in case it's retrievable, or custom otherwise) */
        int code;
        /** Error description text */
        std::string description;
    };

    struct callbacks {
        /** Raised after successful connection */
        void (* on_connected)(void *arg);
        /** Raised after a data chunk has been received */
        void (* on_read)(void *arg, Uint8View data);
        /**
         * Raised after the connection is closed
         * @param error none if closed gracefully
         */
        void (* on_close)(void *arg, std::optional<error> error);
        /** User context for the callbacks */
        void *arg;
    };

    struct connect_parameters {
        /** Event loop for operation */
        event_loop *loop = nullptr;
        /** Address on the peer to connect to */
        const SocketAddress &peer;
        /** Set of the socket callbacks */
        callbacks callbacks = {};
        /** Operation time out value */
        std::optional<std::chrono::microseconds> timeout;
    };

    virtual ~socket() = default;

    socket(socket &&) = default;
    socket &operator=(socket &&) = default;

    socket(const socket &) = delete;
    socket &operator=(const socket &) = delete;

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
    [[nodiscard]] virtual std::optional<error> connect(connect_parameters params) = 0;

    /**
     * Send data to the peer
     * @param data the data
     * @return some error if failed
     */
    [[nodiscard]] virtual std::optional<error> send(Uint8View data) = 0;

    /**
     * Send DNS packet to the peer
     * @param data the packet
     * @return some error if failed
     */
    [[nodiscard]] virtual std::optional<error> send_dns_packet(Uint8View data) = 0;

    /**
     * Set operation time out
     * @param timeout the time out value
     * @return true if successful
     */
    virtual bool set_timeout(std::chrono::microseconds timeout) = 0;

    /**
     * Update socket callbacks. May be used to turn on/off the read events
     * @param cbx the callbacks
     * @return some error if failed
     */
    [[nodiscard]] virtual std::optional<error> set_callbacks(callbacks cbx) = 0;

protected:
    friend class socket_factory;

    struct prepare_fd_callback {
        /** Raised after the descriptor creation */
        ErrString (* func)(void *arg, evutil_socket_t fd,
                           const SocketAddress &peer, const IfIdVariant &outbound_interface);
        /** User context for the callback */
        void *arg;
    };

    Logger log;
    size_t id = 0;
    socket_factory::socket_parameters parameters = {};
    prepare_fd_callback prepare_fd = {};

    socket(const std::string &logger_name,
            socket_factory::socket_parameters parameters, prepare_fd_callback prepare_fd);
};

}
