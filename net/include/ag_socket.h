#pragma once


#include <optional>
#include <chrono>
#include <string>
#include <variant>
#include <event2/event.h>
#include <event2/util.h>
#include <openssl/ssl.h>
#include <ag_defs.h>
#include <ag_net_utils.h>
#include <ag_logger.h>
#include <ag_route_resolver.h>
#include <ag_event_loop.h>


namespace ag {

class socket;

class socket_factory {
public:
    using socket_ptr = std::unique_ptr<socket>;

    struct parameters {
    };

    struct socket_parameters {
        /** Socket protocol */
        utils::transport_protocol proto;
        /** (Optional) name or index of the network interface to route traffic through */
        if_id_variant outbound_interface;
    };

    explicit socket_factory(parameters parameters);
    ~socket_factory() = default;

    socket_factory(socket_factory &&) = default;
    socket_factory &operator=(socket_factory &&) = default;

    socket_factory(const socket_factory &) = delete;
    socket_factory &operator=(const socket_factory &) = delete;

    /**
     * Create a socket basing on the factory and provided parameters
     * @param parameters the socket parameters
     * @return the socket
     */
    [[nodiscard]] socket_ptr make_socket(socket_parameters parameters) const;

    /**
     * Prepare an externally created descriptor in the same way as `make_socket` does
     * @param fd the descriptor to be prepared
     * @param peer the destination peer address
     * @param outbound_interface name or index of the network interface to route traffic through
     * @return some error if failed
     */
    [[nodiscard]] err_string prepare_fd(evutil_socket_t fd,
            const socket_address &peer, const if_id_variant &outbound_interface) const;

private:
    parameters parameters = {};
    route_resolver_ptr router;

    static err_string on_prepare_fd(void *arg, evutil_socket_t fd,
            const socket_address &peer, const if_id_variant &outbound_interface);
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
        void (* on_read)(void *arg, uint8_view data);
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
        const socket_address &peer;
        /** Set of the socket callbacks */
        callbacks callbacks = {};
        /** Operation time out value */
        std::optional<std::chrono::microseconds> timeout;
        /** SSL context in case it's a secured connection */
        std::unique_ptr<SSL, ftor<&SSL_free>> ssl;
    };

    virtual ~socket() = default;

    socket(socket &&) = default;
    socket &operator=(socket &&) = default;

    socket(const socket &) = delete;
    socket &operator=(const socket &) = delete;

    /**
     * Get the socket protocol
     */
    [[nodiscard]] utils::transport_protocol get_protocol() const;

    /**
     * Get underlying file descriptor
     */
    [[nodiscard]] virtual std::optional<evutil_socket_t> get_fd() const = 0;

    /**
     * Get the peer address
     */
    [[nodiscard]] socket_address get_peer() const;

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
    [[nodiscard]] virtual std::optional<error> send(uint8_view data) = 0;

    /**
     * Send DNS packet to the peer
     * @param data the packet
     * @return some error if failed
     */
    [[nodiscard]] virtual std::optional<error> send_dns_packet(uint8_view data) = 0;

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
        err_string (* func)(void *arg, evutil_socket_t fd,
                const socket_address &peer, const if_id_variant &outbound_interface);
        /** User context for the callback */
        void *arg;
    };

    logger log;
    size_t id = 0;
    socket_factory::socket_parameters parameters = {};
    prepare_fd_callback prepare_fd = {};

    socket(const std::string &logger_name,
            socket_factory::socket_parameters parameters, prepare_fd_callback prepare_fd);
};

}
