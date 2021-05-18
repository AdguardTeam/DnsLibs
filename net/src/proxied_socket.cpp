#include "proxied_socket.h"


#define log_sock(s_, lvl_, fmt_, ...) lvl_##log((s_)->log, "[id={}] {}(): " fmt_, (s_)->id, __func__, ##__VA_ARGS__)


using namespace ag;


proxied_socket::proxied_socket(outbound_proxy &outbound_proxy,
        socket_factory::socket_parameters p, prepare_fd_callback prepare_fd)
    : socket(__func__, std::move(p), prepare_fd)
    , proxy(outbound_proxy)
{}

proxied_socket::~proxied_socket() {
    if (this->proxy_id.has_value()) {
        this->proxy.close_connection(this->proxy_id.value());
    }
}

std::optional<evutil_socket_t> proxied_socket::get_fd() const {
    return !this->proxy_id.has_value() ? std::nullopt : this->proxy.get_fd(this->proxy_id.value());
}

std::optional<socket::error> proxied_socket::connect(connect_parameters params) {
    log_sock(this, trace, "{}", params.peer.str());

    if (auto err = this->set_callbacks(params.callbacks); err.has_value()) {
        log_sock(this, dbg, "Failed to set callbacks: {} ({})", err->description, err->code);
        assert(0);
        return err;
    }

    auto r = this->proxy.connect({ params.loop, this->get_protocol(), params.peer,
            { on_connected, on_read, on_close, this }, params.timeout });
    if (auto *e = std::get_if<socket::error>(&r); e != nullptr) {
        return std::move(*e);
    }

    this->proxy_id = std::get<uint32_t>(r);

    return std::nullopt;
}

std::optional<socket::error> proxied_socket::send(uint8_view data) {
    log_sock(this, trace, "{}", data.size());
    return this->proxy.send(this->proxy_id.value(), data);
}

std::optional<socket::error> proxied_socket::send_dns_packet(uint8_view data) {
    log_sock(this, trace, "{}", data.size());

    std::optional<error> err;

    switch (this->get_protocol()) {
    case utils::TP_UDP:
        err = this->proxy.send(this->proxy_id.value(), data);
        break;
    case utils::TP_TCP: {
        uint16_t length = htons(data.size());
        err = this->proxy.send(this->proxy_id.value(), { (uint8_t *)&length, 2 });
        if (!err.has_value()) {
            err = this->proxy.send(this->proxy_id.value(), data);
        }
        break;
    }
    }

    return err;
}

bool proxied_socket::set_timeout(std::chrono::microseconds timeout) {
    log_sock(this, trace, "{}", timeout);
    return this->proxy.set_timeout(this->proxy_id.value(), timeout);
}

std::optional<socket::error> proxied_socket::set_callbacks(struct callbacks cbx) {
    log_sock(this, trace, "...");

    this->callbacks.mtx.lock();
    this->callbacks.val = cbx;
    this->callbacks.mtx.unlock();

    if (this->proxy_id.has_value()) {
        std::optional<socket::error> e = this->proxy.set_callbacks(this->proxy_id.value(),
                {
                        (cbx.on_connected != nullptr) ? on_connected : nullptr,
                        (cbx.on_read != nullptr) ? on_read : nullptr,
                        (cbx.on_close != nullptr) ? on_close : nullptr,
                        this,
                });
        if (e.has_value()) {
            return e;
        }
    }

    return std::nullopt;
}

struct proxied_socket::callbacks proxied_socket::get_callbacks() {
    std::scoped_lock l(this->callbacks.mtx);
    return this->callbacks.val;
}

void proxied_socket::on_connected(void *arg, uint32_t conn_id) {
    auto *self = (proxied_socket *)arg;
    log_sock(self, trace, "...");
    if (struct callbacks cbx = self->get_callbacks(); cbx.on_connected != nullptr) {
        cbx.on_connected(cbx.arg);
    }
}

void proxied_socket::on_read(void *arg, uint8_view data) {
    auto *self = (proxied_socket *)arg;
    log_sock(self, trace, "{}", data.size());
    if (struct callbacks cbx = self->get_callbacks(); cbx.on_read != nullptr) {
        cbx.on_read(cbx.arg, data);
    }
}

void proxied_socket::on_close(void *arg, std::optional<socket::error> error) {
    auto *self = (proxied_socket *)arg;
    if (error.has_value()) {
        log_sock(self, dbg, "{} ({})", error->description, error->code);
    }

    if (struct callbacks cbx = self->get_callbacks(); cbx.on_close != nullptr) {
        cbx.on_close(cbx.arg, std::move(error));
    }
}
