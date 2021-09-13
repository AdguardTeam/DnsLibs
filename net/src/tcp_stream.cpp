#include <ag_utils.h>
#include "tcp_stream.h"
#include <event2/buffer.h>
#include <openssl/err.h>


#define log_stream(s_, lvl_, fmt_, ...) lvl_##log((s_)->log, "[id={}] {}(): " fmt_, (s_)->id, __func__, ##__VA_ARGS__)


using namespace ag;
using namespace std::chrono;


tcp_stream::tcp_stream(socket_factory::socket_parameters p, prepare_fd_callback prepare_fd)
    : socket(__func__, std::move(p), prepare_fd)
{}

std::optional<evutil_socket_t> tcp_stream::get_fd() const {
    return (this->bev != nullptr)
            ? std::make_optional(bufferevent_getfd(this->bev.get()))
            : std::nullopt;
}

std::optional<socket::error> tcp_stream::connect(connect_parameters params) {
    log_stream(this, trace, "{}", params.peer.str());

    static constexpr int OPTIONS =
            BEV_OPT_THREADSAFE | BEV_OPT_DEFER_CALLBACKS | BEV_OPT_UNLOCK_CALLBACKS | BEV_OPT_CLOSE_ON_FREE;
    this->bev.reset(bufferevent_socket_new(params.loop->c_base(), -1, OPTIONS));
    if (this->bev == nullptr) {
        return { { -1, "Failed to create socket buffer event" } };
    }

    if (params.timeout.has_value() && !this->set_timeout(params.timeout.value())) {
        return { { -1, "Failed to set bufferevent timeouts" } };
    }

    if (this->prepare_fd.func != nullptr) {
        bufferevent_setpreparecb(this->bev.get(), on_prepare_fd, this);
    }

    if (auto e = this->set_callbacks(params.callbacks); e.has_value()) {
        log_stream(this, dbg, "Failed to set callbacks");
        return e;
    }

    if (0 != bufferevent_socket_connect(this->bev.get(), params.peer.c_sockaddr(), (int)params.peer.c_socklen())) {
        log_stream(this, dbg, "Failed to start connection");
        int err = evutil_socket_geterror(bufferevent_getfd(this->bev.get()));
        return { { err, evutil_socket_error_to_string(err) } };
    }

    return std::nullopt;
}

std::optional<socket::error> tcp_stream::send(uint8_view data) {
    log_stream(this, trace, "{}", data.size());

    if (0 != bufferevent_write(this->bev.get(), data.data(), data.size())) {
        log_stream(this, dbg, "Failed to write data");
        int err = evutil_socket_geterror(bufferevent_getfd(this->bev.get()));
        return { { err, evutil_socket_error_to_string(err) } };
    }

    if (!this->set_timeout()) {
        return { { -1, "Failed to refresh bufferevent timeouts" } };
    }

    return std::nullopt;
}

std::optional<socket::error> tcp_stream::send_dns_packet(uint8_view data) {
    log_stream(this, trace, "{}", data.size());

    uint16_t length = htons(data.size());
    if (auto e = this->send({ (uint8_t *)&length, 2 }); e.has_value()) {
        return e;
    }

    return this->send(data);
}

std::optional<socket::error> tcp_stream::set_callbacks(struct callbacks cbx) {
    log_stream(this, trace, "...");

    this->guard.lock();
    this->callbacks = cbx;
    this->guard.unlock();

    auto bufferevent_action = (cbx.on_read != nullptr) ? bufferevent_enable : bufferevent_disable;
    if (0 != bufferevent_action(this->bev.get(), EV_READ)) {
        return { { -1, AG_FMT("Failed to {} read event", (cbx.on_read != nullptr) ? "enable" : "disable") } };
    }

    bufferevent_setcb(this->bev.get(),
            (cbx.on_read != nullptr) ? on_read : nullptr,
            nullptr,
            (cbx.on_close != nullptr) ? on_event : nullptr,
            deferred_arg());

    return std::nullopt;
}

bool tcp_stream::set_timeout(microseconds timeout) {
    log_stream(this, trace, "{}", timeout);

    this->guard.lock();
    this->current_timeout = timeout;
    this->guard.unlock();

    return this->set_timeout();
}

bool tcp_stream::set_timeout() {
    this->guard.lock();
    microseconds timeout = this->current_timeout;
    this->guard.unlock();

    const timeval tv = utils::duration_to_timeval(timeout);
    return 0 == bufferevent_set_timeouts(this->bev.get(), &tv, &tv);
}

struct tcp_stream::callbacks tcp_stream::get_callbacks() const {
    std::scoped_lock l(this->guard);
    return this->callbacks;
}

int tcp_stream::on_prepare_fd(int fd, const struct sockaddr *sa, int, void *arg) {
    auto *self = (tcp_stream *)arg;
    err_string err = self->prepare_fd.func(self->prepare_fd.arg, fd,
            ag::socket_address{ sa }, self->parameters.outbound_interface);
    if (err.has_value()) {
        log_stream(self, warn, "Failed to bind socket to interface: {}", err.value());
        return 0;
    }
    return 1;
}

void tcp_stream::on_event(bufferevent *bev, short what, void *arg) {
    auto *self = (tcp_stream *)deferred_arg_to_ptr(arg);
    if (!self) {
        return;
    }

    if (what & BEV_EVENT_CONNECTED) {
        log_stream(self, trace, "Connected");
        if (struct callbacks cbx = self->get_callbacks(); cbx.on_connected != nullptr) {
            cbx.on_connected(cbx.arg);
        }
    } else if (what & BEV_EVENT_TIMEOUT) {
        log_stream(self, trace, "Timed out");
        int err = utils::AG_ETIMEDOUT;
        if (struct callbacks cbx = self->get_callbacks(); cbx.on_close != nullptr) {
            cbx.on_close(cbx.arg, { { err, evutil_socket_error_to_string(err) } });
        }
    } else if (what & BEV_EVENT_ERROR) {
        log_stream(self, trace, "Error");
        error error = { -1 };
        if (int err = evutil_socket_geterror(bufferevent_getfd(bev)); err != 0) {
            error = { err, evutil_socket_error_to_string(err) };
        } else {
            error.description = "Unknown error";
        }
        if (struct callbacks cbx = self->get_callbacks(); cbx.on_close != nullptr) {
            cbx.on_close(cbx.arg, std::move(error));
        }
    } else if (what & BEV_EVENT_EOF) {
        log_stream(self, trace, "EOF");
        if (struct callbacks cbx = self->get_callbacks(); cbx.on_close != nullptr) {
            cbx.on_close(cbx.arg, std::nullopt);
        }
    } else {
        log_stream(self, trace, "Unexpected event: {}", what);
        assert(0);
    }
}

void tcp_stream::on_read(bufferevent *bev, void *arg) {
    auto *self = (tcp_stream *)deferred_arg_to_ptr(arg);
    if (!self) {
        return;
    }

    evbuffer *buffer = bufferevent_get_input(bev);
    auto available_to_read = (ssize_t)evbuffer_get_length(buffer);
    int chunks_num = evbuffer_peek(buffer, available_to_read, nullptr, nullptr, 0);

    evbuffer_iovec chunks[chunks_num];
    int chunks_peeked = evbuffer_peek(buffer, available_to_read, nullptr, chunks, chunks_num);
    for (int i = 0; i < chunks_peeked; ++i) {
        log_stream(self, trace, "{}", chunks[i].iov_len);
        if (struct callbacks cbx = self->get_callbacks(); cbx.on_read != nullptr) {
            cbx.on_read(cbx.arg, { (uint8_t *) chunks[i].iov_base, chunks[i].iov_len });
        }
    }

    evbuffer_drain(buffer, available_to_read);
}
