#include "proxied_socket.h"


#define log_sock(s_, lvl_, fmt_, ...) lvl_##log((s_)->log, "[id={}] {}(): " fmt_, (s_)->id, __func__, ##__VA_ARGS__)


using namespace ag;


proxied_socket::proxied_socket(parameters p)
    : socket(__func__, std::move(p.socket_parameters), p.prepare_fd)
    , proxy(&p.outbound_proxy)
    , proxied_callbacks(p.callbacks)
{}

proxied_socket::~proxied_socket() {
    this->fallback_info.reset();
    if (this->proxy_id.has_value()) {
        this->proxy->close_connection(this->proxy_id.value());
    }
}

std::optional<evutil_socket_t> proxied_socket::get_fd() const {
    return !this->proxy_id.has_value() ? std::nullopt : this->proxy->get_fd(this->proxy_id.value());
}

std::optional<socket::error> proxied_socket::connect(connect_parameters params) {
    log_sock(this, trace, "{}", params.peer.str());

    if (auto err = this->set_callbacks(params.callbacks); err.has_value()) {
        log_sock(this, dbg, "Failed to set callbacks: {} ({})", err->description, err->code);
        assert(0);
        return err;
    }

    auto r = this->proxy->connect({ params.loop, this->get_protocol(), params.peer,
            {
                on_successful_proxy_connection, on_proxy_connection_failed,
                on_connected, on_read, on_close,
                this
            },
            params.timeout
    });
    if (auto *e = std::get_if<socket::error>(&r); e != nullptr) {
        return std::move(*e);
    }

    this->proxy_id = std::get<uint32_t>(r);

    this->fallback_info = std::make_unique<struct fallback_info>();
    this->fallback_info->loop = params.loop;
    this->fallback_info->peer = params.peer;
    this->fallback_info->connect_timestamp = steady_clock::now();
    this->fallback_info->timeout = params.timeout;

    return std::nullopt;
}

std::optional<socket::error> proxied_socket::send(uint8_view data) {
    log_sock(this, trace, "{}", data.size());
    return this->proxy->send(this->proxy_id.value(), data);
}

std::optional<socket::error> proxied_socket::send_dns_packet(uint8_view data) {
    log_sock(this, trace, "{}", data.size());

    std::optional<error> err;

    switch (this->get_protocol()) {
    case utils::TP_UDP:
        err = this->proxy->send(this->proxy_id.value(), data);
        break;
    case utils::TP_TCP: {
        uint16_t length = htons(data.size());
        err = this->proxy->send(this->proxy_id.value(), { (uint8_t *)&length, 2 });
        if (!err.has_value()) {
            err = this->proxy->send(this->proxy_id.value(), data);
        }
        break;
    }
    }

    return err;
}

bool proxied_socket::set_timeout(std::chrono::microseconds timeout) {
    log_sock(this, trace, "{}", timeout);
    if (this->fallback_info != nullptr) {
        this->fallback_info->timeout = timeout;
    }
    return this->proxy->set_timeout(this->proxy_id.value(), timeout);
}

std::optional<socket::error> proxied_socket::set_callbacks(socket::callbacks cbx) {
    log_sock(this, trace, "...");

    std::optional<socket::error> err;

    this->socket_callbacks.mtx.lock();
    this->socket_callbacks.val = cbx;
    this->socket_callbacks.mtx.unlock();

    if (this->proxy_id.has_value()) {
        err = this->proxy->set_callbacks(this->proxy_id.value(),
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

struct socket::callbacks proxied_socket::get_callbacks() {
    std::scoped_lock l(this->socket_callbacks.mtx);
    return this->socket_callbacks.val;
}

void proxied_socket::on_successful_proxy_connection(void *arg) {
    auto *self = (proxied_socket *)arg;
    self->proxied_callbacks.on_successful_proxy_connection(self->proxied_callbacks.arg);
}

void proxied_socket::on_proxy_connection_failed(void *arg, std::optional<int> err) {
    auto *self = (proxied_socket *)arg;

    proxy_connection_failed_result r =
            self->proxied_callbacks.on_proxy_connection_failed(self->proxied_callbacks.arg, err);
    if (std::holds_alternative<close_connection>(r)) {
        return;
    }

    self->fallback_info->proxy = std::get<fallback>(r).proxy;
}

void proxied_socket::on_connected(void *arg, uint32_t conn_id) {
    auto *self = (proxied_socket *)arg;
    log_sock(self, trace, "...");
    self->fallback_info.reset();
    if (socket::callbacks cbx = self->get_callbacks(); cbx.on_connected != nullptr) {
        cbx.on_connected(cbx.arg);
    }
}

void proxied_socket::on_read(void *arg, uint8_view data) {
    auto *self = (proxied_socket *)arg;
    log_sock(self, trace, "{}", data.size());
    if (socket::callbacks cbx = self->get_callbacks(); cbx.on_read != nullptr) {
        cbx.on_read(cbx.arg, data);
    }
}

void proxied_socket::on_close(void *arg, std::optional<socket::error> error) {
    auto *self = (proxied_socket *)arg;
    if (error.has_value()) {
        log_sock(self, dbg, "{} ({})", error->description, error->code);
    }

    if (std::unique_ptr info = std::move(self->fallback_info);
            info != nullptr && info->proxy != nullptr) {
        log_sock(self, dbg, "Falling back to direct connection");
        self->proxy->close_connection(std::exchange(self->proxy_id, std::nullopt).value());
        self->proxy = info->proxy;
        std::chrono::microseconds elapsed =
                std::chrono::duration_cast<std::chrono::microseconds>(steady_clock::now() - info->connect_timestamp);
        self->socket_callbacks.mtx.lock();
        socket::callbacks socket_callbacks = self->socket_callbacks.val;
        self->socket_callbacks.mtx.unlock();
        error = self->connect({
                info->loop, info->peer,
                socket_callbacks,
                info->timeout.has_value()
                        ? std::make_optional<std::chrono::microseconds>(
                                std::max(std::chrono::microseconds(0), info->timeout.value() - elapsed))
                        : std::nullopt,
        });
        if (!error.has_value()) {
            return;
        }
        log_sock(self, dbg, "Failed to fall back");
    }

    if (socket::callbacks cbx = self->get_callbacks(); cbx.on_close != nullptr) {
        cbx.on_close(cbx.arg, std::move(error));
    }
}
