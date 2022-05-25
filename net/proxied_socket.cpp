#include "proxied_socket.h"

#define log_sock(s_, lvl_, fmt_, ...) lvl_##log((s_)->m_log, "[id={}] {}(): " fmt_, (s_)->m_id, __func__, ##__VA_ARGS__)

namespace ag {

ProxiedSocket::ProxiedSocket(Parameters p)
        : Socket(__func__, std::move(p.socket_parameters), p.prepare_fd)
        , m_proxy(&p.outbound_proxy)
        , m_proxied_callbacks(p.callbacks) {
}

ProxiedSocket::~ProxiedSocket() {
    m_fallback_info.reset();
    if (m_proxy_id.has_value()) {
        m_proxy->close_connection(m_proxy_id.value());
    }
}

std::optional<evutil_socket_t> ProxiedSocket::get_fd() const {
    return !m_proxy_id.has_value() ? std::nullopt : m_proxy->get_fd(m_proxy_id.value());
}

std::optional<Socket::Error> ProxiedSocket::connect(ConnectParameters params) {
    log_sock(this, trace, "{}", params.peer.str());

    if (auto err = this->set_callbacks(params.callbacks); err.has_value()) {
        log_sock(this, dbg, "Failed to set callbacks: {} ({})", err->description, err->code);
        assert(0);
        return err;
    }

    auto r = m_proxy->connect({params.loop, this->get_protocol(), params.peer,
            {on_successful_proxy_connection, on_proxy_connection_failed, on_connected, on_read, on_close, this},
            params.timeout});
    if (auto *e = std::get_if<Socket::Error>(&r); e != nullptr) {
        return std::move(*e);
    }

    m_proxy_id = std::get<uint32_t>(r);

    m_fallback_info = std::make_unique<struct FallbackInfo>();
    m_fallback_info->loop = params.loop;
    m_fallback_info->peer = params.peer;
    m_fallback_info->connect_timestamp = SteadyClock::now();
    m_fallback_info->timeout = params.timeout;

    return std::nullopt;
}

std::optional<Socket::Error> ProxiedSocket::send(Uint8View data) {
    log_sock(this, trace, "{}", data.size());
    return m_proxy->send(m_proxy_id.value(), data);
}

std::optional<Socket::Error> ProxiedSocket::send_dns_packet(Uint8View data) {
    log_sock(this, trace, "{}", data.size());

    std::optional<Error> err;

    switch (this->get_protocol()) {
    case utils::TP_UDP:
        err = m_proxy->send(m_proxy_id.value(), data);
        break;
    case utils::TP_TCP: {
        uint16_t length = htons(data.size());
        err = m_proxy->send(m_proxy_id.value(), {(uint8_t *) &length, 2});
        if (!err.has_value()) {
            err = m_proxy->send(m_proxy_id.value(), data);
        }
        break;
    }
    }

    return err;
}

bool ProxiedSocket::set_timeout(Micros timeout) {
    log_sock(this, trace, "{}", timeout);
    if (m_fallback_info != nullptr) {
        m_fallback_info->timeout = timeout;
    }
    return m_proxy->set_timeout(m_proxy_id.value(), timeout);
}

std::optional<Socket::Error> ProxiedSocket::set_callbacks(Socket::Callbacks cbx) {
    log_sock(this, trace, "...");

    std::optional<Socket::Error> err;

    m_socket_callbacks.mtx.lock();
    m_socket_callbacks.val = cbx;
    m_socket_callbacks.mtx.unlock();

    if (m_proxy_id.has_value()) {
        err = m_proxy->set_callbacks(m_proxy_id.value(),
                {
                        on_successful_proxy_connection,
                        on_proxy_connection_failed,
                        (cbx.on_connected != nullptr) ? on_connected : nullptr,
                        (cbx.on_read != nullptr) ? on_read : nullptr,
                        (cbx.on_close != nullptr) ? on_close : nullptr,
                        this,
                });
    }

    return err;
}

struct Socket::Callbacks ProxiedSocket::get_callbacks() {
    std::scoped_lock l(m_socket_callbacks.mtx);
    return m_socket_callbacks.val;
}

void ProxiedSocket::on_successful_proxy_connection(void *arg) {
    auto *self = (ProxiedSocket *) arg;
    self->m_proxied_callbacks.on_successful_proxy_connection(self->m_proxied_callbacks.arg);
}

void ProxiedSocket::on_proxy_connection_failed(void *arg, std::optional<int> err) {
    auto *self = (ProxiedSocket *) arg;

    ProxyConnectionFailedResult r
            = self->m_proxied_callbacks.on_proxy_connection_failed(self->m_proxied_callbacks.arg, err);
    if (std::holds_alternative<CloseConnection>(r)) {
        return;
    }

    self->m_fallback_info->proxy = std::get<Fallback>(r).proxy;
}

void ProxiedSocket::on_connected(void *arg, uint32_t conn_id) {
    auto *self = (ProxiedSocket *) arg;
    log_sock(self, trace, "...");
    self->m_fallback_info.reset();
    if (Socket::Callbacks cbx = self->get_callbacks(); cbx.on_connected != nullptr) {
        cbx.on_connected(cbx.arg);
    }
}

void ProxiedSocket::on_read(void *arg, Uint8View data) {
    auto *self = (ProxiedSocket *) arg;
    log_sock(self, trace, "{}", data.size());
    if (Socket::Callbacks cbx = self->get_callbacks(); cbx.on_read != nullptr) {
        cbx.on_read(cbx.arg, data);
    }
}

void ProxiedSocket::on_close(void *arg, std::optional<Socket::Error> error) {
    auto *self = (ProxiedSocket *) arg;
    if (error.has_value()) {
        log_sock(self, dbg, "{} ({})", error->description, error->code);
    }

    if (std::unique_ptr info = std::move(self->m_fallback_info); info != nullptr && info->proxy != nullptr) {
        log_sock(self, dbg, "Falling back to direct connection");
        self->m_proxy->close_connection(std::exchange(self->m_proxy_id, std::nullopt).value());
        self->m_proxy = info->proxy;
        Micros elapsed = std::chrono::duration_cast<Micros>(SteadyClock::now() - info->connect_timestamp);
        self->m_socket_callbacks.mtx.lock();
        Socket::Callbacks socket_callbacks = self->m_socket_callbacks.val;
        self->m_socket_callbacks.mtx.unlock();
        error = self->connect({
                info->loop,
                info->peer,
                socket_callbacks,
                info->timeout.has_value()
                        ? std::make_optional<Micros>(std::max(Micros(0), info->timeout.value() - elapsed))
                        : std::nullopt,
        });
        if (!error.has_value()) {
            return;
        }
        log_sock(self, dbg, "Failed to fall back");
    }

    if (Socket::Callbacks cbx = self->get_callbacks(); cbx.on_close != nullptr) {
        cbx.on_close(cbx.arg, std::move(error));
    }
}

} // namespace ag
