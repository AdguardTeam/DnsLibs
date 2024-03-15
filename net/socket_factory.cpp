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

SocketFactory::SocketFactory(Parameters parameters)
        : m_parameters(std::move(parameters))
        , m_router(parameters.enable_route_resolver ? RouteResolver::create() : RouteResolverPtr{nullptr}) {
    if (m_parameters.oproxy.settings != nullptr) {
        m_proxy.reset(this->make_proxy());
    }
}

SocketFactory::~SocketFactory() = default;

void SocketFactory::deinit() {
    if (m_proxy) {
        m_proxy->deinit();
        m_proxy.reset();
    }
}

SocketFactory::SocketPtr SocketFactory::make_socket(SocketParameters p) const {
    SocketPtr socket;
    if (p.ignore_proxy_settings || !this->should_route_through_proxy(p.proto)) {
        socket = this->make_direct_socket(std::move(p));
    } else {
        socket = std::make_unique<ProxiedSocket>(ProxiedSocket::Parameters{
                *m_proxy,
                std::move(p),
                {on_prepare_fd, (void *) this},
                {
                        [](void *) {},
                        [](void *, Error<SocketError>) {
                            return ProxiedSocket::OCFA_CLOSE_CONNECTION;
                        },
                        [](void *) -> ProxiedSocket::Fallback {
                            return {};
                        },
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
    if (peer.is_loopback()) {
        return {};
    }
    if (const uint32_t *if_index = std::get_if<uint32_t>(&outbound_interface)) {
        auto err = ag::utils::bind_socket_to_if(fd, peer.c_sockaddr()->sa_family, *if_index);
        return (err == nullptr) ? nullptr : make_error(SocketError::AE_BIND_TO_IF_ERROR, err);
    }
    if (const std::string *if_name = std::get_if<std::string>(&outbound_interface)) {
        auto err = ag::utils::bind_socket_to_if(fd, peer.c_sockaddr()->sa_family, if_name->c_str());
        return (err == nullptr) ? nullptr : make_error(SocketError::AE_BIND_TO_IF_ERROR, err);
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
    if (!m_proxy->get_supported_protocols().test(proto)) {
        return false;
    }

    return true;
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

} // namespace ag::dns
