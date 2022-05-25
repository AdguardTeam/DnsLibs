#include "tcp_stream.h"
#include "common/time_utils.h"
#include "common/utils.h"
#include <cassert>
#include <event2/buffer.h>
#include <openssl/err.h>

namespace ag {

#define log_stream(s_, lvl_, fmt_, ...)                                                                                \
    lvl_##log((s_)->m_log, "[id={}] {}(): " fmt_, (s_)->m_id, __func__, ##__VA_ARGS__)

using namespace std::chrono;

TcpStream::TcpStream(SocketFactory::SocketParameters p, PrepareFdCallback prepare_fd)
        : Socket(__func__, std::move(p), prepare_fd)
        , m_deferred_arg(this) {
}

std::optional<evutil_socket_t> TcpStream::get_fd() const {
    return (m_bev != nullptr) ? std::make_optional(bufferevent_getfd(m_bev.get())) : std::nullopt;
}

std::optional<Socket::Error> TcpStream::connect(ConnectParameters params) {
    log_stream(this, trace, "{}", params.peer.str());

    static constexpr int OPTIONS
            = BEV_OPT_THREADSAFE | BEV_OPT_DEFER_CALLBACKS | BEV_OPT_UNLOCK_CALLBACKS | BEV_OPT_CLOSE_ON_FREE;
    m_bev.reset(bufferevent_socket_new(params.loop->c_base(), -1, OPTIONS));
    if (m_bev == nullptr) {
        return {{-1, "Failed to create socket buffer event"}};
    }

    if (m_prepare_fd.func != nullptr) {
        bufferevent_setpreparecb(m_bev.get(), on_prepare_fd, this);
    }

    if (auto e = this->set_callbacks(params.callbacks); e.has_value()) {
        log_stream(this, dbg, "Failed to set callbacks");
        return e;
    }

    if (0 != bufferevent_socket_connect(m_bev.get(), params.peer.c_sockaddr(), (int) params.peer.c_socklen())) {
        log_stream(this, dbg, "Failed to start connection");
        int err = evutil_socket_geterror(bufferevent_getfd(m_bev.get()));
        return {{err, evutil_socket_error_to_string(err)}};
    }

    if (params.timeout.has_value() && !this->set_timeout(params.timeout.value())) {
        return {{-1, "Failed to set time out"}};
    }

    return std::nullopt;
}

std::optional<Socket::Error> TcpStream::send(Uint8View data) {
    log_stream(this, trace, "{}", data.size());

    if (0 != bufferevent_write(m_bev.get(), data.data(), data.size())) {
        log_stream(this, dbg, "Failed to write data");
        int err = evutil_socket_geterror(bufferevent_getfd(m_bev.get()));
        return {{err, evutil_socket_error_to_string(err)}};
    }

    if (!this->set_timeout()) {
        return {{-1, "Failed to refresh time out"}};
    }

    return std::nullopt;
}

std::optional<Socket::Error> TcpStream::send_dns_packet(Uint8View data) {
    log_stream(this, trace, "{}", data.size());

    uint16_t length = htons(data.size());
    if (auto e = this->send({(uint8_t *) &length, 2}); e.has_value()) {
        return e;
    }

    return this->send(data);
}

std::optional<Socket::Error> TcpStream::set_callbacks(Callbacks cbx) {
    log_stream(this, trace, "...");

    m_guard.lock();
    m_callbacks = cbx;
    m_guard.unlock();

    if (m_bev == nullptr) {
        return std::nullopt;
    }

    auto bufferevent_action = (cbx.on_read != nullptr) ? bufferevent_enable : bufferevent_disable;
    if (0 != bufferevent_action(m_bev.get(), EV_READ)) {
        return {{-1, AG_FMT("Failed to {} read event", (cbx.on_read != nullptr) ? "enable" : "disable")}};
    }

    bufferevent_setcb(m_bev.get(), (cbx.on_read != nullptr) ? on_read : nullptr, nullptr,
            (cbx.on_close != nullptr) ? on_event : nullptr, m_deferred_arg.value());

    return std::nullopt;
}

bool TcpStream::set_timeout(microseconds timeout) {
    log_stream(this, trace, "{}", timeout);

    m_guard.lock();
    m_current_timeout = timeout;
    m_guard.unlock();

    return this->set_timeout();
}

bool TcpStream::set_timeout() {
    std::scoped_lock l(m_guard);
    if (m_bev == nullptr) {
        return true;
    }

    if (!m_current_timeout.has_value()) {
        this->reset_timeout_nolock();
        return true;
    }

    const timeval tv = duration_to_timeval(m_current_timeout.value());
    if (m_timer == nullptr) {
        m_timer.reset(event_new(bufferevent_get_base(m_bev.get()), -1, EV_TIMEOUT, on_timeout, m_deferred_arg.value()));
    }
    return m_timer != nullptr && 0 == evtimer_add(m_timer.get(), &tv);
}

void TcpStream::reset_timeout_locked() {
    std::scoped_lock l(m_guard);
    reset_timeout_nolock();
}

void TcpStream::reset_timeout_nolock() {
    m_timer.reset();
    m_current_timeout.reset();
}

struct TcpStream::Callbacks TcpStream::get_callbacks() const {
    std::scoped_lock l(m_guard);
    return m_callbacks;
}

int TcpStream::on_prepare_fd(int fd, const struct sockaddr *sa, int, void *arg) {
    auto *self = (TcpStream *) arg;
    ErrString err = self->m_prepare_fd.func(
            self->m_prepare_fd.arg, fd, SocketAddress{sa}, self->m_parameters.outbound_interface);
    if (err.has_value()) {
        log_stream(self, warn, "Failed to bind socket to interface: {}", err.value());
        return 0;
    }
    return 1;
}

void TcpStream::on_event(bufferevent *bev, short what, void *arg) {
    auto *self = (TcpStream *) DeferredArg::to_ptr(arg);
    if (!self) {
        return;
    }

    if (what & BEV_EVENT_CONNECTED) {
        log_stream(self, trace, "Connected");
        [[maybe_unused]] bool _ = self->set_timeout();

        if (Callbacks cbx = self->get_callbacks(); cbx.on_connected != nullptr) {
            cbx.on_connected(cbx.arg);
        }
    } else if (what & BEV_EVENT_ERROR) {
        log_stream(self, trace, "Error");
        self->reset_timeout_locked();

        Error error = {-1};
        if (int err = evutil_socket_geterror(bufferevent_getfd(bev)); err != 0) {
            error = {err, evutil_socket_error_to_string(err)};
        } else {
            error.description = "Unknown error";
        }
        if (Callbacks cbx = self->get_callbacks(); cbx.on_close != nullptr) {
            cbx.on_close(cbx.arg, std::move(error));
        }
    } else if (what & BEV_EVENT_EOF) {
        log_stream(self, trace, "EOF");
        self->reset_timeout_locked();

        if (Callbacks cbx = self->get_callbacks(); cbx.on_close != nullptr) {
            cbx.on_close(cbx.arg, std::nullopt);
        }
    } else {
        log_stream(self, trace, "Unexpected event: {}", what);
        assert(0);
    }
}

void TcpStream::on_read(bufferevent *bev, void *arg) {
    auto *self = (TcpStream *) DeferredArg::to_ptr(arg);
    if (!self) {
        return;
    }

    [[maybe_unused]] bool _ = self->set_timeout();

    evbuffer *buffer = bufferevent_get_input(bev);
    auto available_to_read = (ssize_t) evbuffer_get_length(buffer);
    int chunks_num = evbuffer_peek(buffer, available_to_read, nullptr, nullptr, 0);

    evbuffer_iovec chunks[chunks_num];
    int chunks_peeked = evbuffer_peek(buffer, available_to_read, nullptr, chunks, chunks_num);
    for (int i = 0; i < chunks_peeked; ++i) {
        log_stream(self, trace, "{}", chunks[i].iov_len);
        if (Callbacks cbx = self->get_callbacks(); cbx.on_read != nullptr) {
            cbx.on_read(cbx.arg, {(uint8_t *) chunks[i].iov_base, chunks[i].iov_len});
        }
    }

    evbuffer_drain(buffer, available_to_read);
}

void TcpStream::on_timeout(evutil_socket_t, short, void *arg) {
    auto *self = (TcpStream *) DeferredArg::to_ptr(arg);
    if (!self) {
        return;
    }

    log_stream(self, trace, "Timed out");
    self->reset_timeout_locked();

    int err = utils::AG_ETIMEDOUT;
    if (Callbacks cbx = self->get_callbacks(); cbx.on_close != nullptr) {
        cbx.on_close(cbx.arg, {{err, evutil_socket_error_to_string(err)}});
    }
}

} // namespace ag
