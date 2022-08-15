#pragma once


#include <variant>
#include "dns/net/socket.h"
#include "common/clock.h"
#include "outbound_proxy.h"


namespace ag::dns {

class ProxiedSocket : public Socket {
public:
    struct CloseConnection {};
    struct Fallback {
        OutboundProxy *proxy;
    };
    using ProxyConnectionFailedResult = std::variant<
            CloseConnection,
            Fallback
    >;

    struct Callbacks {
        /** Raised after the connection to the proxy server succeeded */
        void (* on_successful_proxy_connection)(void *arg);
        /** Raised after an error on the connection to the proxy server */
        ProxyConnectionFailedResult (* on_proxy_connection_failed)(void *arg, Error<SocketError> err);
        /** User context for the callback */
        void *arg;
    };

    struct Parameters {
        OutboundProxy &outbound_proxy;
        SocketFactory::SocketParameters socket_parameters;
        PrepareFdCallback prepare_fd = {};
        Callbacks callbacks = {};
    };

    explicit ProxiedSocket(Parameters p);
    ~ProxiedSocket() override;

    ProxiedSocket(ProxiedSocket &&) = delete;
    ProxiedSocket &operator=(ProxiedSocket &&) = delete;
    ProxiedSocket(const ProxiedSocket &) = delete;
    ProxiedSocket &operator=(const ProxiedSocket &) = delete;

private:
    struct FallbackInfo {
        EventLoop *loop = nullptr;
        SocketAddress peer;
        SteadyClock::time_point connect_timestamp;
        std::optional<Micros> timeout;
        OutboundProxy *proxy = nullptr;
    };

    OutboundProxy *m_proxy = nullptr;
    WithMtx<Socket::Callbacks> m_socket_callbacks = {};
    std::optional<uint32_t> m_proxy_id;
    Callbacks m_proxied_callbacks = {};
    std::unique_ptr<FallbackInfo> m_fallback_info;

    [[nodiscard]] std::optional<evutil_socket_t> get_fd() const override;
    [[nodiscard]] Error<SocketError> connect(ConnectParameters params) override;
    [[nodiscard]] Error<SocketError> send(Uint8View data) override;
    [[nodiscard]] Error<SocketError> send_dns_packet(Uint8View data) override;
    [[nodiscard]] bool set_timeout(Micros timeout) override;
    [[nodiscard]] Error<SocketError> set_callbacks(Socket::Callbacks cbx) override;

    [[nodiscard]] Socket::Callbacks get_callbacks();

    static void on_successful_proxy_connection(void *arg);
    static void on_proxy_connection_failed(void *arg, Error<SocketError> err);
    static void on_connected(void *arg, uint32_t conn_id);
    static void on_read(void *arg, Uint8View data);
    static void on_close(void *arg, Error<SocketError> error);
};

} // namespace ag::dns
