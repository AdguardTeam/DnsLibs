#include <ag_utils.h>
#include "udp_socket.h"

#if defined(__linux__) || defined(__LINUX__) || defined(__MACH__)
    #include <unistd.h>
#elif defined(_WIN32)
    #include <windows.h>
    #include <io.h>
#endif


#define log_sock(s_, lvl_, fmt_, ...) lvl_##log((s_)->log, "[id={}] {}(): " fmt_, (s_)->id, __func__, ##__VA_ARGS__)


using namespace ag;


udp_socket::udp_socket(socket_factory::socket_parameters p, prepare_fd_callback prepare_fd)
    : socket(__func__, std::move(p), prepare_fd), deferred_arg(this)
{}

std::optional<evutil_socket_t> udp_socket::get_fd() const {
    return (this->socket_event != nullptr)
            ? std::make_optional(event_get_fd(this->socket_event.get()))
            : std::nullopt;
}

std::optional<socket::error> udp_socket::connect(connect_parameters params) {
    log_sock(this, trace, "{}", params.peer.str());

    std::optional<error> result;

    evutil_socket_t fd = ::socket(params.peer.c_sockaddr()->sa_family, SOCK_DGRAM, 0);
    if (fd < 0) {
        log_sock(this, dbg, "Failed to create socket");
        goto error;
    }

    if (err_string err; this->prepare_fd.func != nullptr
            && (err = this->prepare_fd.func(this->prepare_fd.arg, fd, params.peer, this->parameters.outbound_interface))
                    .has_value()) {
        result = { -1, AG_FMT("Failed to prepare descriptor: {}", err.value()) };
        goto error;
    }

    if (0 != evutil_make_socket_nonblocking(fd)) {
        log_sock(this, dbg, "Failed to make socket non-blocking");
        goto error;
    }

    if (0 != ::connect(fd, params.peer.c_sockaddr(), params.peer.c_socklen())) {
        log_sock(this, dbg, "Failed to connect");
        goto error;
    }

    this->socket_event.reset(
            event_new(params.loop->c_base(), fd, EV_READ | EV_PERSIST, on_event, deferred_arg.value()));
    if (this->socket_event == nullptr) {
        result = { -1, "Failed to create event" };
        goto error;
    }

    this->timeout = params.timeout;
    if (result = this->set_callbacks(params.callbacks); result.has_value()) {
        log_sock(this, dbg, "Failed to set callbacks");
        goto error;
    }

    params.loop->submit([this] () {
        if (struct callbacks cbx = this->get_callbacks(); cbx.on_connected != nullptr) {
            cbx.on_connected(cbx.arg);
        }
    });

    goto exit;

    error:
    if (!result.has_value()) {
        int err = evutil_socket_geterror(fd);
        result = { err, evutil_socket_error_to_string(err) };
    }
    evutil_closesocket(fd);

    exit:
    return result;
}

std::optional<socket::error> udp_socket::send(uint8_view data) {
    log_sock(this, trace, "{}", data.size());

    if (ssize_t r = ::send(event_get_fd(this->socket_event.get()), (const char *)data.data(), data.size(), 0);
            r < 0) {
        int err = evutil_socket_geterror(event_get_fd(this->socket_event.get()));
        if (!utils::socket_error_is_eagain((int)r)) {
            return { { err, evutil_socket_error_to_string(err) } };
        }
    }

    return std::nullopt;
}

std::optional<socket::error> udp_socket::send_dns_packet(uint8_view data) {
    return this->send(data);
}

bool udp_socket::set_timeout(std::chrono::microseconds to) {
    log_sock(this, trace, "{}", to);

    this->guard.lock();
    this->timeout = to;
    this->guard.unlock();

    if (this->socket_event != nullptr && event_pending(this->socket_event.get(), EV_TIMEOUT | EV_READ, nullptr)) {
        const timeval tv = utils::duration_to_timeval(to);
        if (0 != event_add(this->socket_event.get(), &tv)) {
            log_sock(this, dbg, "Failed to add event in event base");
            return false;
        }
    }
    return true;
}

std::optional<socket::error> udp_socket::set_callbacks(struct callbacks cbx) {
    log_sock(this, trace, "...");

    this->guard.lock();
    this->callbacks = cbx;
    this->guard.unlock();

    if (cbx.on_read != nullptr) {
        const timeval tv = utils::duration_to_timeval(this->timeout.value_or(std::chrono::microseconds(0)));
        if (0 != event_add(this->socket_event.get(), this->timeout.has_value() ? &tv : nullptr)) {
            return { { -1, "Failed to add event in event base" } };
        }
    } else {
        if (0 != event_del(this->socket_event.get())) {
            return { { -1, "Failed to cancel event" } };
        }
    }

    return std::nullopt;
}

struct udp_socket::callbacks udp_socket::get_callbacks() const {
    std::scoped_lock l(this->guard);
    return this->callbacks;
}

void udp_socket::on_event(evutil_socket_t fd, short what, void *arg) {
    auto *self = (udp_socket *)deferred_arg_to_ptr(arg);
    if (!self) {
        return;
    }

    if (what & EV_READ) {
        uint8_t read_buffer[65 * 1024];
        ssize_t r = ::recv(fd, (char *)read_buffer, sizeof(read_buffer), 0);
        log_sock(self, trace, "{}", r);
        if (r > 0) {
            if (struct callbacks cbx = self->get_callbacks(); cbx.on_read != nullptr) {
                cbx.on_read(cbx.arg, { read_buffer, (size_t) r });
            }
        } else {
            int err = evutil_socket_geterror(fd);
            if (!utils::socket_error_is_eagain(err)) {
                if (struct callbacks cbx = self->get_callbacks(); cbx.on_close != nullptr) {
                    cbx.on_close(cbx.arg, { { err, evutil_socket_error_to_string(err) } });
                }
            }
        }
    } else if (what & EV_TIMEOUT) {
        log_sock(self, trace, "Timed out");
        int err = utils::AG_ETIMEDOUT;
        if (struct callbacks cbx = self->get_callbacks(); cbx.on_close != nullptr) {
            cbx.on_close(cbx.arg, { { err, evutil_socket_error_to_string(err) } });
        }
    } else {
        log_sock(self, trace, "Unexpected event: {}", what);
        assert(0);
    }
}

udp_socket::~udp_socket() {
    log_sock(this, trace, "Destroyed");
    if (socket_event) {
        evutil_socket_t fd = event_get_fd(socket_event.get());
        // epoll is not happy when deleting events after close
        event_del(socket_event.get());
        evutil_closesocket(fd);
    }
}
