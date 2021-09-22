#include "outbound_direct_proxy.h"


using namespace ag;


direct_oproxy::direct_oproxy(struct parameters parameters)
    : outbound_proxy(__func__, nullptr, std::move(parameters))
{}

void direct_oproxy::reset_connections() {
    std::scoped_lock l(this->guard);

    for (auto &[conn_id, conn] : this->connections) {
        [[maybe_unused]] auto e = conn.socket->set_callbacks({});
        conn.parameters.loop->submit(
                [this, conn_id = conn_id] () {
                    std::optional<callbacks> cbx;

                    {
                        std::scoped_lock l(this->guard);
                        auto it = this->connections.find(conn_id);
                        if (it == this->connections.end()) {
                            return;
                        }

                        cbx = it->second.parameters.callbacks;
                        if (cbx->on_close == nullptr) {
                            this->connections.erase(it);
                        }
                    }

                    if (cbx.has_value() && cbx->on_close != nullptr) {
                        cbx->on_close(cbx->arg, { { -1, "Reset re-routed directly connection" } });
                    }
                });
    }
}

outbound_proxy::protocols_set direct_oproxy::get_supported_protocols() const {
    return (1 << utils::TP_TCP) | (1 << utils::TP_UDP);
}

std::optional<evutil_socket_t> direct_oproxy::get_fd(uint32_t conn_id) const {
    std::scoped_lock l(this->guard);
    auto it = this->connections.find(conn_id);
    return (it != this->connections.end()) ? it->second.socket->get_fd() : std::nullopt;
}

std::optional<socket::error> direct_oproxy::send(uint32_t conn_id, uint8_view data) {
    std::scoped_lock l(this->guard);
    auto it = this->connections.find(conn_id);
    return (it != this->connections.end()) ? it->second.socket->send(data) : socket::error{ -1, "Not found" };
}

bool direct_oproxy::set_timeout(uint32_t conn_id, std::chrono::microseconds timeout) {
    std::scoped_lock l(this->guard);
    auto it = this->connections.find(conn_id);
    return (it != this->connections.end()) ? it->second.socket->set_timeout(timeout) : false;
}

std::optional<socket::error> direct_oproxy::set_callbacks(uint32_t conn_id, callbacks cbx) {
    std::scoped_lock l(this->guard);
    auto it = this->connections.find(conn_id);
    if (it == this->connections.end()) {
        return { { -1, "Not found" } };
    }

    connection &conn = it->second;
    conn.parameters.callbacks = cbx;
    if (auto e = conn.socket->set_callbacks({
                    (cbx.on_connected != nullptr) ? on_connected : nullptr,
                    (cbx.on_read != nullptr) ? on_read : nullptr,
                    (cbx.on_close != nullptr) ? on_close : nullptr,
                    &conn
                });
            e.has_value()) {
        return e;
    }

    return std::nullopt;
}

void direct_oproxy::close_connection(uint32_t conn_id) {
    std::scoped_lock l(this->guard);
    auto it = this->connections.find(conn_id);
    if (it == this->connections.end()) {
        return;
    }

    connection &conn = it->second;
    [[maybe_unused]] auto e = conn.socket->set_callbacks({});
    conn.parameters.loop->submit(
            [this, conn_id] () {
                std::scoped_lock l(this->guard);
                this->connections.erase(conn_id);
            });
}

std::optional<socket::error> direct_oproxy::connect_to_proxy(uint32_t conn_id, const connect_parameters &parameters) {
    return this->connect_through_proxy(conn_id, parameters);
}

std::optional<socket::error> direct_oproxy::connect_through_proxy(uint32_t conn_id, const connect_parameters &parameters) {
    std::scoped_lock l(this->guard);
    connection &conn = this->connections.emplace(conn_id,
            connection{
                this,
                conn_id,
                this->parameters.make_socket.func(this->parameters.make_socket.arg, parameters.proto, std::nullopt),
                parameters,
            }).first->second;
    return conn.socket->connect({
            parameters.loop,
            parameters.peer,
            { on_connected, on_read, on_close, &conn },
            parameters.timeout,
    });
}

void direct_oproxy::on_connected(void *arg) {
    auto *conn = (connection *)arg;
    conn->parameters.callbacks.on_connected(conn->parameters.callbacks.arg, conn->id);
}

void direct_oproxy::on_read(void *arg, uint8_view data) {
    auto *conn = (connection *)arg;
    conn->parameters.callbacks.on_read(conn->parameters.callbacks.arg, data);
}

void direct_oproxy::on_close(void *arg, std::optional<socket::error> error) {
    auto *conn = (connection *)arg;
    conn->parameters.callbacks.on_close(conn->parameters.callbacks.arg, std::move(error));
}
