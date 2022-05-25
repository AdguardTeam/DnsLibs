#pragma once


#include <memory>
#include <variant>
#include <bitset>
#include <optional>
#include <magic_enum.hpp>

#include "common/defs.h"
#include "common/net_utils.h"
#include "common/socket_address.h"
#include "common/logger.h"
#include "net/outbound_proxy_settings.h"
#include "net/socket.h"


namespace ag {

class OutboundProxy {
public:
    using ConnectResult = std::variant<
            /** Connection id if successful */
            uint32_t,
            /** Error if failed */
            Socket::Error>;
    using ProtocolsSet = std::bitset<magic_enum::enum_count<utils::TransportProtocol>()>;

    struct Callbacks {
        /** Raised after the connection to the proxy server succeeded */
        void (* on_successful_proxy_connection)(void *arg);
        /** Raised after an error on the connection to the proxy server */
        void (* on_proxy_connection_failed)(void *arg, std::optional<int> err);
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
        void (* on_close)(void *arg, std::optional<Socket::Error> error);
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
        MakeSocketCallback make_socket = {};
    };

    struct ConnectParameters {
        /** Event loop for operation */
        EventLoop *loop = nullptr;
        /** Connection protocol */
        utils::TransportProtocol proto;
        /** Address on the peer to connect to */
        SocketAddress peer;
        /** Set of the proxy callbacks */
        Callbacks callbacks = {};
        /** Operation time out value */
        std::optional<Micros> timeout;
    };

    virtual ~OutboundProxy() = default;

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
    [[nodiscard]] virtual std::optional<Socket::Error> send(uint32_t conn_id, Uint8View data) = 0;

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
    [[nodiscard]] virtual std::optional<Socket::Error> set_callbacks(uint32_t conn_id, Callbacks cbx) = 0;

    /**
     * Close the connection
     * @param conn_id the connection ID
     */
    virtual void close_connection(uint32_t conn_id) = 0;

protected:
    Logger m_log;
    size_t m_id = 0;
    const OutboundProxySettings *m_settings = nullptr;
    Parameters m_parameters = {};

    OutboundProxy(const std::string &logger_name, const OutboundProxySettings *settings, Parameters parameters);

    /**
     * Connect to the proxy server
     */
    [[nodiscard]] virtual std::optional<Socket::Error> connect_to_proxy(uint32_t conn_id, const ConnectParameters &parameters) = 0;

    /**
     * Connect to the peer through the proxy server
     */
    [[nodiscard]] virtual std::optional<Socket::Error> connect_through_proxy(uint32_t conn_id, const ConnectParameters &parameters) = 0;

    /**
     * Get the next connection ID
     */
    [[nodiscard]] static uint32_t get_next_connection_id();
};

}
