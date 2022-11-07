#pragma once


#include <bitset>
#include <magic_enum.hpp>
#include <memory>
#include <optional>
#include <variant>

#include "common/defs.h"
#include "common/net_utils.h"
#include "common/socket_address.h"
#include "common/logger.h"
#include "dns/net/outbound_proxy_settings.h"
#include "dns/net/socket.h"


namespace ag::dns {

class OutboundProxy {
public:
    using ConnectResult = Result<uint32_t /* Connection ID */, SocketError>;
    using ProtocolsSet = std::bitset<magic_enum::enum_count<utils::TransportProtocol>()>;

    struct Callbacks {
        /** Raised after the connection to the proxy server succeeded */
        void (* on_successful_proxy_connection)(void *arg);
        /** Raised after an error on the connection to the proxy server */
        void (* on_proxy_connection_failed)(void *arg, Error<SocketError> err);
        /**
         * Raised after tunnel to a peer through the proxy is established
         * @param conn_id ID of the opened connection
         */
        void (* on_connected)(void *arg, uint32_t conn_id);
        /** Raised after a data chunk has been received */
        void (* on_read)(void *arg, Uint8View data);
        /**
         * Raised after the tunnel is closed
         * @param conn_id id of the connection on which error happened
         * @param error none if closed gracefully
         */
        void (* on_close)(void *arg, Error<SocketError> error);
        /** User context for the callbacks */
        void *arg;
    };

    struct MakeSocketCallback {
        /** Raised when proxy wants to create a socket */
        SocketFactory::SocketPtr (* func)(void *arg, utils::TransportProtocol proto,
                std::optional<SocketFactory::SecureSocketParameters> secure_parameters);
        /** User context for the callback */
        void *arg;
    };

    struct Parameters {
        const CertificateVerifier *verifier = nullptr;
        SocketFactory::ProxyBootstrapper *bootstrapper = nullptr;
        MakeSocketCallback make_socket = {};
    };

    struct ConnectParameters {
        /** Event loop for operation */
        EventLoop *loop = nullptr;
        /** Connection protocol */
        utils::TransportProtocol proto;
        /** Address of the peer to connect to */
        SocketAddress peer;
        /** Set of the proxy callbacks */
        Callbacks callbacks = {};
        /** Operation time out value */
        std::optional<Micros> timeout;
        /** (Optional) name or index of the network interface to route traffic through */
        IfIdVariant outbound_interface;
    };

    virtual ~OutboundProxy();

    /**
     * Connect to the peer via proxy
     * @param parameters the connection parameters
     * @return see `connect_result`
     */
    [[nodiscard]] ConnectResult connect(ConnectParameters parameters);

    /**
     * Get a set of the supported protocols
     */
    [[nodiscard]] virtual ProtocolsSet get_supported_protocols() const = 0;

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
    [[nodiscard]] virtual Error<SocketError> send(uint32_t conn_id, Uint8View data) = 0;

    /**
     * Set operation time out
     * @param timeout the time out value
     * @return true if successful
     */
    virtual bool set_timeout(uint32_t conn_id, Micros timeout) = 0;

    /**
     * Update socket callbacks. May be used to turn on/off the read events
     * @param conn_id the connection ID
     * @param cbx the callbacks
     * @return some error if failed
     */
    [[nodiscard]] Error<SocketError> set_callbacks(uint32_t conn_id, Callbacks cbx);

    /**
     * Close the connection
     * @param conn_id the connection ID
     */
    void close_connection(uint32_t conn_id);

protected:
    Logger m_log;
    size_t m_id = 0;
    const OutboundProxySettings *m_settings = nullptr;
    std::optional<SocketAddress> m_resolved_proxy_address;
    Parameters m_parameters = {};
    HashMap<uint32_t, ConnectParameters> m_bootstrap_waiters;

    OutboundProxy(const std::string &logger_name, const OutboundProxySettings *settings, Parameters parameters);

    /**
     * Connect to the proxy server
     */
    [[nodiscard]] virtual Error<SocketError> connect_to_proxy(uint32_t conn_id, const ConnectParameters &parameters) = 0;

    /**
     * Connect to the peer through the proxy server
     */
    [[nodiscard]] virtual Error<SocketError> connect_through_proxy(uint32_t conn_id, const ConnectParameters &parameters) = 0;

    /**
     * Update socket callbacks. May be used to turn on/off the read events
     */
    [[nodiscard]] virtual Error<SocketError> set_callbacks_impl(uint32_t conn_id, Callbacks cbx) = 0;

    /**
     * Close the connection
     */
    virtual void close_connection_impl(uint32_t conn_id) = 0;

    /**
     * Get the next connection ID
     */
    [[nodiscard]] static uint32_t get_next_connection_id();

private:
    void on_bootstrap_ready(std::optional<SocketAddress> address);
    void on_bootstrap_ready(Error<SocketError> address);
};

} // namespace ag::dns
