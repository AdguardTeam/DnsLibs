#include "outbound_direct_proxy.h"

namespace ag {

DirectOProxy::DirectOProxy(Parameters parameters)
        : OutboundProxy(__func__, nullptr, std::move(parameters)) {
}

void DirectOProxy::reset_connections() {
    std::scoped_lock l(m_guard);

    for (auto &[conn_id, conn] : m_connections) {
        [[maybe_unused]] auto e = conn.socket->set_callbacks({});
        conn.parameters.loop->submit([this, conn_id = conn_id]() {
            std::optional<Callbacks> cbx;

            {
                std::scoped_lock l(m_guard);
                auto it = m_connections.find(conn_id);
                if (it == m_connections.end()) {
                    return;
                }

                cbx = it->second.parameters.callbacks;
                if (cbx->on_close == nullptr) {
                    m_connections.erase(it);
                }
            }

            if (cbx.has_value() && cbx->on_close != nullptr) {
                cbx->on_close(cbx->arg, {{-1, "Reset re-routed directly connection"}});
            }
        });
    }
}

OutboundProxy::ProtocolsSet DirectOProxy::get_supported_protocols() const {
    return (1 << utils::TP_TCP) | (1 << utils::TP_UDP);
}

std::optional<evutil_socket_t> DirectOProxy::get_fd(uint32_t conn_id) const {
    std::scoped_lock l(m_guard);
    auto it = m_connections.find(conn_id);
    return (it != m_connections.end()) ? it->second.socket->get_fd() : std::nullopt;
}

std::optional<Socket::Error> DirectOProxy::send(uint32_t conn_id, Uint8View data) {
    std::scoped_lock l(m_guard);
    auto it = m_connections.find(conn_id);
    return (it != m_connections.end()) ? it->second.socket->send(data) : Socket::Error{-1, "Not found"};
}

bool DirectOProxy::set_timeout(uint32_t conn_id, Micros timeout) {
    std::scoped_lock l(m_guard);
    auto it = m_connections.find(conn_id);
    return (it != m_connections.end()) ? it->second.socket->set_timeout(timeout) : false;
}

std::optional<Socket::Error> DirectOProxy::set_callbacks(uint32_t conn_id, Callbacks cbx) {
    std::scoped_lock l(m_guard);
    auto it = m_connections.find(conn_id);
    if (it == m_connections.end()) {
        return {{-1, "Not found"}};
    }

    Connection &conn = it->second;
    conn.parameters.callbacks = cbx;
    if (auto e = conn.socket->set_callbacks({(cbx.on_connected != nullptr) ? on_connected : nullptr,
                (cbx.on_read != nullptr) ? on_read : nullptr, (cbx.on_close != nullptr) ? on_close : nullptr, &conn});
            e.has_value()) {
        return e;
    }

    return std::nullopt;
}

void DirectOProxy::close_connection(uint32_t conn_id) {
    std::scoped_lock l(m_guard);
    auto node = m_connections.extract(conn_id);
    if (node.empty()) {
        return;
    }

    Connection &conn = node.mapped();
    m_closing_connections.insert(std::move(node));

    [[maybe_unused]] auto e = conn.socket->set_callbacks({});
    conn.parameters.callbacks = {};
    conn.parameters.loop->submit([this, conn_id]() {
        std::scoped_lock l(m_guard);
        m_closing_connections.erase(conn_id);
    });
}

std::optional<Socket::Error> DirectOProxy::connect_to_proxy(uint32_t conn_id, const ConnectParameters &parameters) {
    return this->connect_through_proxy(conn_id, parameters);
}

std::optional<Socket::Error> DirectOProxy::connect_through_proxy(
        uint32_t conn_id, const ConnectParameters &parameters) {
    std::scoped_lock l(m_guard);
    Connection &conn = m_connections
                               .emplace(conn_id,
                                       Connection{
                                               this,
                                               conn_id,
                                               m_parameters.make_socket.func(
                                                       m_parameters.make_socket.arg, parameters.proto, std::nullopt),
                                               parameters,
                                       })
                               .first->second;
    std::optional err = conn.socket->connect({
            parameters.loop,
            parameters.peer,
            {on_connected, on_read, on_close, &conn},
            parameters.timeout,
    });
    if (err.has_value()) {
        m_connections.erase(conn_id);
    }

    return err;
}

void DirectOProxy::on_connected(void *arg) {
    auto *conn = (Connection *) arg;
    conn->parameters.callbacks.on_connected(conn->parameters.callbacks.arg, conn->id);
}

void DirectOProxy::on_read(void *arg, Uint8View data) {
    auto *conn = (Connection *) arg;
    conn->parameters.callbacks.on_read(conn->parameters.callbacks.arg, data);
}

void DirectOProxy::on_close(void *arg, std::optional<Socket::Error> error) {
    auto *conn = (Connection *) arg;
    conn->parameters.callbacks.on_close(conn->parameters.callbacks.arg, std::move(error));
}

} // namespace ag
