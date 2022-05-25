#include "udp_socket.h"
#include "common/time_utils.h"
#include "common/utils.h"
#include <cassert>

#if defined(__linux__) || defined(__LINUX__) || defined(__MACH__)
#include <unistd.h>
#elif defined(_WIN32)
#include <io.h>
#include <windows.h>
#endif

namespace ag {

#define log_sock(s_, lvl_, fmt_, ...) lvl_##log((s_)->m_log, "[id={}] {}(): " fmt_, (s_)->m_id, __func__, ##__VA_ARGS__)

UdpSocket::UdpSocket(SocketFactory::SocketParameters p, PrepareFdCallback prepare_fd)
        : Socket(__func__, std::move(p), prepare_fd)
        , m_deferred_arg(this) {
}

std::optional<evutil_socket_t> UdpSocket::get_fd() const {
    return (m_socket_event != nullptr) ? std::make_optional(event_get_fd(m_socket_event.get())) : std::nullopt;
}

std::optional<Socket::Error> UdpSocket::connect(ConnectParameters params) {
    log_sock(this, trace, "{}", params.peer.str());

    evutil_socket_t fd = -1;
    std::optional<Error> result;

    if (m_event_loop != nullptr) {
        assert(0);
        result = {-1, "Already connected"};
        goto error;
    }

    m_event_loop = params.loop;

    fd = ::socket(params.peer.c_sockaddr()->sa_family, SOCK_DGRAM, 0);
    if (fd < 0) {
        log_sock(this, dbg, "Failed to create socket");
        goto error;
    }

    if (ErrString err; m_prepare_fd.func != nullptr
            && (err = m_prepare_fd.func(m_prepare_fd.arg, fd, params.peer, m_parameters.outbound_interface))
                       .has_value()) {
        result = {-1, AG_FMT("Failed to prepare descriptor: {}", err.value())};
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

    m_socket_event.reset(event_new(params.loop->c_base(), fd, EV_READ | EV_PERSIST, on_event, m_deferred_arg.value()));
    if (m_socket_event == nullptr) {
        result = {-1, "Failed to create event"};
        goto error;
    }

    m_timeout = params.timeout;
    if (result = this->set_callbacks(params.callbacks); result.has_value()) {
        log_sock(this, dbg, "Failed to set callbacks");
        goto error;
    }

    m_connect_notify_task_id = params.loop->schedule(Micros{0}, [this]() {
        if (Callbacks cbx = this->get_callbacks(); cbx.on_connected != nullptr) {
            cbx.on_connected(cbx.arg);
        }
    });

    goto exit;

error:
    if (!result.has_value()) {
        int err = evutil_socket_geterror(fd);
        result = {err, evutil_socket_error_to_string(err)};
    }
    evutil_closesocket(fd);

exit:
    return result;
}

std::optional<Socket::Error> UdpSocket::send(Uint8View data) {
    log_sock(this, trace, "{}", data.size());

    if (ssize_t r = ::send(event_get_fd(m_socket_event.get()), (const char *) data.data(), data.size(), 0); r < 0) {
        int err = evutil_socket_geterror(event_get_fd(m_socket_event.get()));
        if (!utils::socket_error_is_eagain((int) r)) {
            return {{err, evutil_socket_error_to_string(err)}};
        }
    }

    return std::nullopt;
}

std::optional<Socket::Error> UdpSocket::send_dns_packet(Uint8View data) {
    return this->send(data);
}

bool UdpSocket::set_timeout(Micros to) {
    log_sock(this, trace, "{}", to);

    m_guard.lock();
    m_timeout = to;
    m_guard.unlock();

    if (m_socket_event != nullptr && event_pending(m_socket_event.get(), EV_TIMEOUT | EV_READ, nullptr)) {
        const timeval tv = duration_to_timeval(to);
        if (0 != event_add(m_socket_event.get(), &tv)) {
            log_sock(this, dbg, "Failed to add event in event base");
            return false;
        }
    }
    return true;
}

std::optional<Socket::Error> UdpSocket::set_callbacks(Callbacks cbx) {
    log_sock(this, trace, "...");

    m_guard.lock();
    m_callbacks = cbx;
    m_guard.unlock();

    if (m_socket_event == nullptr) {
        return std::nullopt;
    }

    if (cbx.on_read != nullptr) {
        const timeval tv = duration_to_timeval(m_timeout.value_or(Micros(0)));
        if (0 != event_add(m_socket_event.get(), m_timeout.has_value() ? &tv : nullptr)) {
            return {{-1, "Failed to add event in event base"}};
        }
    } else {
        if (0 != event_del(m_socket_event.get())) {
            return {{-1, "Failed to cancel event"}};
        }
    }

    return std::nullopt;
}

struct UdpSocket::Callbacks UdpSocket::get_callbacks() const {
    std::scoped_lock l(m_guard);
    return m_callbacks;
}

void UdpSocket::on_event(evutil_socket_t fd, short what, void *arg) {
    auto *self = (UdpSocket *) DeferredArg::to_ptr(arg);
    if (!self) {
        return;
    }

    if (what & EV_READ) {
        uint8_t read_buffer[65 * 1024];
        ssize_t r = ::recv(fd, (char *) read_buffer, sizeof(read_buffer), 0);
        log_sock(self, trace, "{}", r);
        if (r > 0) {
            if (Callbacks cbx = self->get_callbacks(); cbx.on_read != nullptr) {
                cbx.on_read(cbx.arg, {read_buffer, (size_t) r});
            }
        } else {
            int err = evutil_socket_geterror(fd);
            if (!utils::socket_error_is_eagain(err)) {
                if (Callbacks cbx = self->get_callbacks(); cbx.on_close != nullptr) {
                    cbx.on_close(cbx.arg, {{err, evutil_socket_error_to_string(err)}});
                }
            }
        }
    } else if (what & EV_TIMEOUT) {
        log_sock(self, trace, "Timed out");
        int err = utils::AG_ETIMEDOUT;
        if (Callbacks cbx = self->get_callbacks(); cbx.on_close != nullptr) {
            cbx.on_close(cbx.arg, {{err, evutil_socket_error_to_string(err)}});
        }
    } else {
        log_sock(self, trace, "Unexpected event: {}", what);
        assert(0);
    }
}

UdpSocket::~UdpSocket() {
    log_sock(this, trace, "Destroyed");
    m_event_loop->cancel(m_connect_notify_task_id);
    if (m_socket_event) {
        evutil_socket_t fd = event_get_fd(m_socket_event.get());
        // epoll is not happy when deleting events after close
        event_del(m_socket_event.get());
        evutil_closesocket(fd);
    }
}

} // namespace ag
