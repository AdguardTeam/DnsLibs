#pragma once


#include <memory>
#include <variant>
#include <bitset>
#include <optional>
#include <magic_enum.hpp>
#include <ag_outbound_proxy_settings.h>
#include <ag_defs.h>
#include <ag_net_utils.h>
#include <ag_socket_address.h>
#include <ag_logger.h>
#include <ag_socket.h>


namespace ag {

class outbound_proxy {
public:
    using connect_result = std::variant<
            /** Connection id if successful */
            uint32_t,
            /** Error if failed */
            socket::error>;
    using protocols_set = std::bitset<magic_enum::enum_count<utils::transport_protocol>()>;

    struct callbacks {
        /**
         * Raised after tunnel to a peer through the proxy is established
         * @param conn_id ID of the opened connection
         */
        void (* on_connected)(void *arg, uint32_t conn_id);
        /** Raised after a data chunk has been received */
        void (* on_read)(void *arg, uint8_view data);
        /**
         * Raised after the tunnel is closed
         * @param conn_id id of the connection on which error happened
         * @param error none if closed gracefully
         */
        void (* on_close)(void *arg, std::optional<socket::error> error);
        /** User context for the callbacks */
        void *arg;
    };

    struct make_socket_callback {
        /** Raised when proxy wants to create a socket */
        socket_factory::socket_ptr (* func)(void *arg, utils::transport_protocol proto,
                std::optional<socket_factory::secure_socket_parameters> secure_parameters);
        /** User context for the callback */
        void *arg;
    };

    struct parameters {
        const certificate_verifier *verifier = nullptr;
        make_socket_callback make_socket = {};
    };

    struct connect_parameters {
        /** Event loop for operation */
        event_loop *loop = nullptr;
        /** Connection protocol */
        utils::transport_protocol proto;
        /** Address on the peer to connect to */
        socket_address peer;
        /** Set of the proxy callbacks */
        callbacks callbacks = {};
        /** Operation time out value */
        std::optional<std::chrono::microseconds> timeout;
    };

    virtual ~outbound_proxy() = default;

    /**
     * Connect to the peer via proxy
     * @param parameters the connection parameters
     * @return see `connect_result`
     */
    [[nodiscard]] connect_result connect(connect_parameters parameters);

    /**
     * Get a set of the supported protocols
     */
    [[nodiscard]] virtual protocols_set get_supported_protocols() const = 0;

    /**
     * Get underlying socket file descriptor
     * @param conn_id the connection ID
     * @return some descriptor if available
     */
    [[nodiscard]] virtual std::optional<evutil_socket_t> get_fd(uint32_t conn_id) const = 0;

    /**
     * Send data via the proxied connection
     * @param conn_id the connection ID
     * @param data the data
     * @return some error if failed
     */
    [[nodiscard]] virtual std::optional<socket::error> send(uint32_t conn_id, uint8_view data) = 0;

    /**
     * Set operation time out
     * @param timeout the time out value
     * @return true if successful
     */
    virtual bool set_timeout(uint32_t conn_id, std::chrono::microseconds timeout) = 0;

    /**
     * Update socket callbacks. May be used to turn on/off the read events
     * @param conn_id the connection ID
     * @param cbx the callbacks
     * @return some error if failed
     */
    [[nodiscard]] virtual std::optional<socket::error> set_callbacks(uint32_t conn_id, callbacks cbx) = 0;

    /**
     * Close the connection
     * @param conn_id the connection ID
     */
    virtual void close_connection(uint32_t conn_id) = 0;

protected:
    logger log;
    size_t id = 0;
    const outbound_proxy_settings *settings = nullptr;
    struct parameters parameters = {};

    outbound_proxy(const std::string &logger_name, const outbound_proxy_settings *settings, struct parameters parameters);

    /**
     * Connect to the proxy server
     */
    [[nodiscard]] virtual std::optional<socket::error> connect_to_proxy(uint32_t conn_id, const connect_parameters &parameters) = 0;

    /**
     * Connect to the peer through the proxy server
     */
    [[nodiscard]] virtual std::optional<socket::error> connect_through_proxy(uint32_t conn_id, const connect_parameters &parameters) = 0;

    /**
     * Get the next connection ID
     */
    [[nodiscard]] static uint32_t get_next_connection_id();
};

}
