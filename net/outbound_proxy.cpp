#include "outbound_proxy.h"

#include <atomic>
#include <cassert>
#include <utility>

#include "dns/net/outbound_proxy_settings.h"

using namespace ag::dns;

static std::atomic_size_t g_next_id = {0};
static std::atomic_uint32_t g_next_connection_id = {0};

OutboundProxy::OutboundProxy(
        const std::string &logger_name, const OutboundProxySettings *settings, Parameters parameters)
        : m_log(logger_name)
        , m_id(g_next_id.fetch_add(1, std::memory_order_relaxed))
        , m_settings(settings)
        , m_resolved_proxy_address([](const OutboundProxySettings *settings) -> std::optional<SocketAddress> {
            if (settings == nullptr) {
                return std::nullopt;
            }
            auto addr = std::make_optional<SocketAddress>(settings->address, settings->port);
            if (!addr->valid()) {
                addr.reset();
            }
            return addr;
        }(m_settings))
        , m_parameters(parameters) {
}

OutboundProxy::~OutboundProxy() = default;

void OutboundProxy::deinit() {
    this->on_bootstrap_ready(make_error(SocketError::AE_OUTBOUND_PROXY_ERROR, "Proxy has been destroyed"));
    assert(m_bootstrap_waiters.empty());
    this->deinit_impl();
}

OutboundProxy::ConnectResult OutboundProxy::connect(ConnectParameters p) {
    uint32_t conn_id = get_next_connection_id();

    if (!m_resolved_proxy_address.has_value()
            && m_parameters.bootstrapper != nullptr && m_settings != nullptr
            && !utils::str_to_socket_address(m_settings->address).valid()) {
        m_bootstrap_waiters.emplace(conn_id, p);
        if (m_bootstrap_waiters.size() == 1) {
            // @todo: handle different outbound network interfaces or make sure it's always the same one
            m_parameters.bootstrapper->resolve(m_settings->address, m_settings->bootstrap,
                    std::chrono::duration_cast<Millis>(p.timeout.value_or(Micros::max())), p.outbound_interface,
                    [this](std::optional<SocketAddress> resolved) {
                        this->on_bootstrap_ready(resolved);
                    });
        }

        return conn_id;
    }

    if (auto e = this->connect_to_proxy(conn_id, p)) {
        return e;
    }

    return conn_id;
}

ag::Error<SocketError> OutboundProxy::set_callbacks(uint32_t conn_id, Callbacks cbx) {
    if (auto it = m_bootstrap_waiters.find(conn_id); it != m_bootstrap_waiters.end()) {
        it->second.callbacks = cbx;
        return nullptr;
    }

    return this->set_callbacks_impl(conn_id, cbx);
}

void OutboundProxy::close_connection(uint32_t conn_id) {
    if (0 == m_bootstrap_waiters.erase(conn_id)) {
        this->close_connection_impl(conn_id);
    }
}

uint32_t OutboundProxy::get_next_connection_id() {
    return g_next_connection_id.fetch_add(1, std::memory_order_relaxed);
}

void OutboundProxy::on_bootstrap_ready(std::optional<SocketAddress> resolved) {
    if (!resolved.has_value()) {
        on_bootstrap_ready(make_error(SocketError::AE_OUTBOUND_PROXY_ERROR, "Bootstrap failure"));
        return;
    }

    m_resolved_proxy_address = resolved;
    m_resolved_proxy_address->set_port(m_settings->port);
    on_bootstrap_ready(nullptr);
}

void OutboundProxy::on_bootstrap_ready(Error<SocketError> bootstrap_error) {
    decltype(m_bootstrap_waiters) waiters = std::exchange(m_bootstrap_waiters, {});
    for (auto &[conn_id, parameters] : waiters) {
        Error<SocketError> error = bootstrap_error;
        if (error == nullptr) {
            error = this->connect_to_proxy(conn_id, parameters);
        }

        if (error != nullptr && parameters.callbacks.on_close != nullptr) {
            parameters.callbacks.on_close(parameters.callbacks.arg, error);
        }
    }
}

bool ag::dns::oproxy_protocol_supports_hostname(OutboundProxyProtocol protocol) {
    switch (protocol) {
    case OutboundProxyProtocol::HTTP_CONNECT:
    case OutboundProxyProtocol::HTTPS_CONNECT:
    case OutboundProxyProtocol::SOCKS5:
    case OutboundProxyProtocol::SOCKS5_UDP:
        return true;
    case OutboundProxyProtocol::SOCKS4:
        return false;
    }
    assert(0);
    return false;
}
