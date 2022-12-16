#include "common/clock.h"
#include "dns/common/event_loop.h"
#include "dns/net/socket.h"
#include "outbound_direct_proxy.h"
#include "outbound_http_proxy.h"
#include "outbound_proxy.h"
#include "outbound_socks_proxy.h"
#include "proxied_socket.h"
#include "secured_socket.h"
#include "tcp_stream.h"
#include "udp_socket.h"

namespace ag::dns {

static constexpr Secs PROXY_UNAVAILABLE_TIMEOUT(10);
static constexpr Secs PROXY_AVAILABLE_TIMEOUT(3);

enum proxy_availability_status {
    /// There were no connections to the proxy server recently
    PAS_UNKNOWN,
    /// There was a successful connection to the proxy server recently
    PAS_AVAILABLE,
    /// All the recent connections to the proxy server had failed
    PAS_UNAVAILABLE,
};

struct SocketFactory::OutboundProxyState {
    EventLoop *loop = nullptr;
    /// The main proxy
    std::unique_ptr<OutboundProxy> main_proxy;
    /// The fallback proxy: used in case of the main one is not available
    std::unique_ptr<OutboundProxy> fallback_proxy;

    /// Whether the proxy is available. If not, the behavior depends on
    /// `outbound_proxy_settings#ignore_if_unavailable` flag
    ExpiringValue<proxy_availability_status, PAS_UNKNOWN> availability_status;
    /// Resetting bypassed connections task
    std::optional<EventLoop::TaskId> reset_task;
    /// The next reset event subscriber ID
    uint32_t next_subscriber_id = 0;
    /// The reset event subscribers
    HashMap<uint32_t, ResetBypassedProxyConnectionsSubscriber> reset_subscribers;

    static void on_successful_proxy_connection(void *arg) {
        auto *self = (SocketFactory *) arg;
        ((DirectOProxy *) self->m_proxy->fallback_proxy.get())->reset_connections();
        self->m_proxy->reset_task.reset();
    }

    static ProxiedSocket::ProxyConnectionFailedResult on_proxy_connection_failed(void *arg, Error<SocketError> err) {
        auto *self = (SocketFactory *) arg;
        switch (self->on_proxy_connection_failed(std::move(err))) {
        case SFPCFR_CLOSE_CONNECTION:
            break;
        case SFPCFR_RETRY_DIRECTLY:
            return ProxiedSocket::Fallback{self->m_proxy->fallback_proxy.get()};
        }
        return ProxiedSocket::CloseConnection{};
    }

    ~OutboundProxyState() {
        if (this->reset_task.has_value()) {
            this->loop->cancel(std::exchange(this->reset_task, std::nullopt).value());
        }

        if (this->main_proxy != nullptr) {
            this->main_proxy->deinit();
            this->main_proxy.reset();
        }

        if (this->fallback_proxy != nullptr) {
            this->fallback_proxy->deinit();
            this->fallback_proxy.reset();
        }
    }
};

SocketFactory::SocketFactory(struct Parameters parameters)
        : m_parameters(std::move(parameters))
        , m_router(parameters.enable_route_resolver ? RouteResolver::create() : RouteResolverPtr{nullptr}) {
    if (m_parameters.oproxy.settings != nullptr) {
        m_proxy = std::make_unique<OutboundProxyState>();
        m_proxy->loop = &m_parameters.loop;
        m_proxy->main_proxy.reset(this->make_proxy());
        m_proxy->fallback_proxy.reset(this->make_fallback_proxy());
    }
}

SocketFactory::~SocketFactory() = default;

void SocketFactory::deinit() {
    m_proxy.reset();
}

SocketFactory::SocketPtr SocketFactory::make_socket(SocketParameters p) const {
    SocketPtr socket;
    if (p.ignore_proxy_settings || !this->should_route_through_proxy(p.proto)) {
        socket = this->make_direct_socket(std::move(p));
    } else {
        socket = std::make_unique<ProxiedSocket>(ProxiedSocket::Parameters{
                *m_proxy->main_proxy,
                std::move(p),
                {on_prepare_fd, (void *) this},
                {
                        OutboundProxyState::on_successful_proxy_connection,
                        OutboundProxyState::on_proxy_connection_failed,
                        (void *) this,
                },
        });
    }

    return socket;
}

SocketFactory::SocketPtr SocketFactory::make_secured_socket(
        SocketParameters p, SecureSocketParameters secure_parameters) const {
    return this->make_secured_socket(this->make_socket(std::move(p)), std::move(secure_parameters));
}

SocketFactory::SocketPtr SocketFactory::make_direct_socket(SocketParameters p) const {
    SocketPtr socket;

    Socket::PrepareFdCallback prepare_fd = {on_prepare_fd, (void *) this};

    switch (p.proto) {
    case utils::TP_TCP:
        socket = std::make_unique<TcpStream>(std::move(p), prepare_fd);
        break;
    case utils::TP_UDP:
        socket = std::make_unique<UdpSocket>(std::move(p), prepare_fd);
        break;
    }

    return socket;
}

SocketFactory::SocketPtr SocketFactory::make_secured_socket(
        SocketPtr underlying_socket, SecureSocketParameters secure_parameters) const {
    return std::make_unique<SecuredSocket>(
            std::move(underlying_socket), m_parameters.verifier.get(), std::move(secure_parameters));
}

Error<SocketError> SocketFactory::prepare_fd(
        evutil_socket_t fd, const SocketAddress &peer, const IfIdVariant &outbound_interface) const {
    if (const uint32_t *if_index = std::get_if<uint32_t>(&outbound_interface)) {
        return make_error(SocketError::AE_BIND_TO_IF_ERROR,
                ag::utils::bind_socket_to_if(fd, peer.c_sockaddr()->sa_family, *if_index));
    }
    if (const std::string *if_name = std::get_if<std::string>(&outbound_interface)) {
        return make_error(SocketError::AE_BIND_TO_IF_ERROR,
                ag::utils::bind_socket_to_if(fd, peer.c_sockaddr()->sa_family, if_name->c_str()));
    }
    if (m_router == nullptr) {
        return {};
    }

    if (auto idx = m_router->resolve(peer); idx.has_value()) {
        auto err = ag::utils::bind_socket_to_if(fd, peer.c_sockaddr()->sa_family, *idx);
        if (err) {
            err.reset();
            m_router->flush_cache();
            if (idx = m_router->resolve(peer); idx.has_value()) {
                err = ag::utils::bind_socket_to_if(fd, peer.c_sockaddr()->sa_family, *idx);
                if (err) {
                    return make_error(SocketError::AE_BIND_TO_IF_ERROR, err);
                }
            }
        }
    }

    return {};
}

const OutboundProxySettings *SocketFactory::get_outbound_proxy_settings() const {
    return m_parameters.oproxy.settings;
}

const CertificateVerifier *SocketFactory::get_certificate_verifier() const {
    return m_parameters.verifier.get();
}

bool SocketFactory::should_route_through_proxy(utils::TransportProtocol proto) const {
    if (m_proxy == nullptr) {
        return false;
    }
    if (!m_proxy->main_proxy->get_supported_protocols().test(proto)) {
        return false;
    }

    return m_proxy->availability_status.get() != PAS_UNAVAILABLE
            || !this->get_outbound_proxy_settings()->ignore_if_unavailable;
}

bool SocketFactory::is_proxy_available() const {
    const OutboundProxySettings *settings = this->get_outbound_proxy_settings();
    if (settings == nullptr || m_proxy == nullptr) {
        return false;
    }

    if (!settings->ignore_if_unavailable) {
        return true;
    }

    return m_proxy->availability_status.get() != PAS_UNAVAILABLE;
}

void SocketFactory::on_successful_proxy_connection() {
    m_proxy->availability_status = {PAS_AVAILABLE, PROXY_AVAILABLE_TIMEOUT};
}

SocketFactory::ProxyConectionFailedResult SocketFactory::on_proxy_connection_failed(Error<SocketError> err) {
    if (!err || err->value() != SocketError::AE_CONNECTION_REFUSED) {
        return SFPCFR_CLOSE_CONNECTION;
    }

    if (!this->get_outbound_proxy_settings()->ignore_if_unavailable) {
        return SFPCFR_CLOSE_CONNECTION;
    }

    if (m_proxy->availability_status.get() != PAS_AVAILABLE) {
        m_proxy->availability_status = {PAS_UNAVAILABLE, PROXY_UNAVAILABLE_TIMEOUT};
    }

    if (!m_proxy->reset_task.has_value()) {
        this->subscribe_to_reset_bypassed_proxy_connections_event({on_reset_bypassed_proxy_connections, this});

        m_proxy->reset_task = m_parameters.loop.schedule(PROXY_UNAVAILABLE_TIMEOUT, [this]() {
            m_proxy->reset_task.reset();
            decltype(m_proxy->reset_subscribers) subscribers = std::exchange(m_proxy->reset_subscribers, {});
            for (auto &[_, s] : subscribers) {
                s.func(s.arg);
            }
        });
    }

    return SFPCFR_RETRY_DIRECTLY;
}

uint32_t SocketFactory::subscribe_to_reset_bypassed_proxy_connections_event(
        ResetBypassedProxyConnectionsSubscriber subscriber) {
    return m_proxy->reset_subscribers.emplace(m_proxy->next_subscriber_id++, subscriber).first->first;
}

void SocketFactory::unsubscribe_from_reset_bypassed_proxy_connections_event(uint32_t id) {
    m_proxy->reset_subscribers.erase(id);
}

Error<SocketError> SocketFactory::on_prepare_fd(
        void *arg, evutil_socket_t fd, const SocketAddress &peer, const IfIdVariant &outbound_interface) {
    auto *self = (SocketFactory *) arg;
    return self->prepare_fd(fd, peer, outbound_interface);
}

OutboundProxy *SocketFactory::make_proxy() const {
    struct OutboundProxy::Parameters oproxy_params = {
            .verifier = m_parameters.verifier.get(),
            .bootstrapper = m_parameters.oproxy.bootstrapper.get(),
            .make_socket = {on_make_proxy_socket, (void *) this},
    };

    OutboundProxy *oproxy = nullptr;
    switch (m_parameters.oproxy.settings->protocol) {
    case OutboundProxyProtocol::HTTP_CONNECT:
    case OutboundProxyProtocol::HTTPS_CONNECT:
        oproxy = new HttpOProxy(m_parameters.oproxy.settings, oproxy_params);
        break;
    case OutboundProxyProtocol::SOCKS4:
    case OutboundProxyProtocol::SOCKS5:
    case OutboundProxyProtocol::SOCKS5_UDP:
        oproxy = new SocksOProxy(m_parameters.oproxy.settings, oproxy_params);
        break;
    }

    return oproxy;
}

OutboundProxy *SocketFactory::make_fallback_proxy() const {
    return new DirectOProxy({
            .verifier = m_parameters.verifier.get(),
            .make_socket = {on_make_proxy_socket, (void *) this},
    });
}

SocketFactory::SocketPtr SocketFactory::on_make_proxy_socket(
        void *arg, utils::TransportProtocol proto, std::optional<SecureSocketParameters> secure_parameters) {
    auto *self = (SocketFactory *) arg;
    SocketPtr s = self->make_direct_socket({proto});
    if (secure_parameters.has_value()) {
        s = self->make_secured_socket(std::move(s), std::move(secure_parameters.value()));
    }
    return s;
}

void SocketFactory::on_reset_bypassed_proxy_connections(void *arg) {
    auto *self = (SocketFactory *) arg;
    self->m_proxy->reset_task.reset();
    ((DirectOProxy *) self->m_proxy->fallback_proxy.get())->reset_connections();
}

} // namespace ag::dns
