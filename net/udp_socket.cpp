#include <cassert>
#include <uv.h>

#include "common/time_utils.h"
#include "common/utils.h"

#include "udp_socket.h"

namespace ag::dns {

#define log_sock(s_, lvl_, fmt_, ...) lvl_##log((s_)->m_log, "[id={}] {}(): " fmt_, (s_)->m_id, __func__, ##__VA_ARGS__)

UdpSocket::UdpSocket(SocketFactory::SocketParameters p, PrepareFdCallback prepare_fd)
        : Socket(__func__, std::move(p), prepare_fd) {
}

std::optional<evutil_socket_t> UdpSocket::get_fd() const {
    uv_os_fd_t fd;
    if (0 == uv_fileno((uv_handle_t *) m_udp->raw(), &fd)) {
        return std::make_optional((evutil_socket_t) fd);
    }
    return std::nullopt;
}

Error<SocketError> UdpSocket::connect(ConnectParameters params) {
    log_sock(this, trace, "{}", params.peer.str());

    Error<SocketError> result;

    if (m_connected) {
        assert(0);
        return make_error(SocketError::AE_ALREADY_CONNECTED);
    }

    m_udp = Uv<uv_udp_t>::create_with_parent(this);
    if (int err = uv_udp_init_ex(params.loop->handle(), m_udp->raw(), (uint8_t)params.peer.c_sockaddr()->sa_family); err != 0) {
        return make_error(SocketError::AE_SOCK_ERROR, "Failed to initialize UDP handle", make_error(uv_errno_t(err)));
    }

    m_timer = Uv<uv_timer_t>::create_with_parent(this);
    if (int err = uv_timer_init(params.loop->handle(), m_timer->raw()); err != 0) {
        auto error = make_error(uv_errno_t(err));
        return make_error(SocketError::AE_SOCK_ERROR, "Failed to initialize timer", error);
    }

    uv_os_fd_t fd;
    uv_fileno((uv_handle_t *) m_udp->raw(), &fd);
    if (ErrString err; m_prepare_fd.func != nullptr
            && (err = m_prepare_fd.func(m_prepare_fd.arg, (evutil_socket_t) fd, params.peer, m_parameters.outbound_interface))
                    .has_value()) {
        return make_error(SocketError::AE_PREPARE_ERROR, AG_FMT("Failed to prepare descriptor: {}", err.value()));
    }

    Error<SocketError> sock_err;
    if (int err = uv_udp_connect(m_udp->raw(), params.peer.c_sockaddr()); err != 0) {
        auto error = make_error(uv_errno_t(err));
        log_sock(this, dbg, "Failed to connect: {}", error->str());
        sock_err = (err == UV_ECONNREFUSED)
                ? make_error(SocketError::AE_CONNECTION_REFUSED, error)
                : make_error(SocketError::AE_SOCK_ERROR, error);
    }
    params.loop->submit([sock_err, weak = m_udp->weak_from_this()](){
        if (auto *udp = weak.lock().get()) {
            if (sock_err) {
                if (Callbacks cbx = static_cast<UdpSocket *>(udp->parent())->get_callbacks(); cbx.on_close != nullptr) {
                    cbx.on_close(cbx.arg, sock_err);
                }
                return;
            }
            if (Callbacks cbx = static_cast<UdpSocket *>(udp->parent())->get_callbacks(); cbx.on_connected != nullptr) {
                cbx.on_connected(cbx.arg);
            }
        }
    });

    if (auto e = this->set_callbacks(params.callbacks); result) {
        log_sock(this, dbg, "Failed to set callbacks: {}", result->str());
        return e;
    }

    if (params.timeout.has_value() && !this->set_timeout(params.timeout.value())) {
        return make_error(SocketError::AE_SET_TIMEOUT_ERROR);
    }

    return {};
}

Error<SocketError> UdpSocket::send(Uint8View data) {
    struct Write {
        std::vector<uint8_t> buf;
        uv_udp_send_t req{};
        static void on_write(uv_udp_send_t *req, int status [[maybe_unused]]) {
            delete (Write *) req->data;
        }
    };
    Write *wr = new Write{.buf{data.begin(), data.end()}};
    wr->req.data = wr;
    uv_buf_t uv_buf = uv_buf_init((char *)wr->buf.data(), wr->buf.size());
    uv_os_fd_t fd;
    uv_fileno((uv_handle_t *) m_udp->raw(), &fd);
    log_sock(this, trace, "Writing {} bytes to {}", data.size(), fd);
    if (int err = uv_udp_send(&wr->req, m_udp->raw(), &uv_buf, 1, nullptr, &Write::on_write)) {
        Write::on_write(&wr->req, err);
        auto error = make_error(uv_errno_t(err));
        return make_error(SocketError::AE_SOCK_ERROR, error);
    }
    return {};
}

Error<SocketError> UdpSocket::send_dns_packet(Uint8View data) {
    return this->send(data);
}

bool UdpSocket::set_timeout(std::chrono::microseconds to) {
    log_sock(this, trace, "{}", to);

    m_current_timeout = to;

    return update_timer();
}

Error<SocketError> UdpSocket::set_callbacks(Callbacks cbx) {
    log_sock(this, trace, "...");

    m_callbacks = cbx;

    update_read_status();

    return {};
}

void UdpSocket::update_read_status() {
    log_sock(this, trace, "");
    if (m_udp != nullptr) {
        if (m_callbacks.on_read != nullptr) {
            int r = uv_udp_recv_start(m_udp->raw(), allocate_read, on_read);
            log_sock(this, trace, "read_start: {}", r);
        } else {
            int r = uv_udp_recv_stop(m_udp->raw());
            log_sock(this, trace, "read_stop: {}", r);
            m_reads.clear();
        }
    }
}


struct UdpSocket::Callbacks UdpSocket::get_callbacks() const {
    return m_callbacks;
}

UdpSocket::~UdpSocket() {
    log_sock(this, trace, "Destroyed");
    if (m_udp) {
        uv_udp_recv_stop(m_udp->raw());
    }
}

void UdpSocket::on_timeout(uv_timer_t *handle) {
    auto self = (UdpSocket *) Uv<uv_poll_t>::parent_from_data(handle->data);
    if (!self) {
        return;
    }
    log_sock(self, trace, "Timed out");
    uv_timer_stop(self->m_timer->raw());
    if (Callbacks cbx = self->get_callbacks(); cbx.on_close != nullptr) {
        cbx.on_close(cbx.arg, make_error(SocketError::AE_TIMED_OUT));
        // Object may be destroyed in on_close
        return;
    }
}

bool UdpSocket::update_timer() {
    if (m_timer) {
        if (m_current_timeout) {
            int timeout_ms = ag::to_millis(*m_current_timeout).count();
            return 0 == uv_timer_start(m_timer->raw(), &on_timeout, timeout_ms, 0);
        } else {
            return 0 == uv_timer_stop(m_timer->raw());
        }
    }
    return true;
}

void UdpSocket::allocate_read(uv_handle_t *handle, size_t size, uv_buf_t *buf) {
    auto *self = (UdpSocket *) Uv<uv_tcp_t>::parent_from_data(handle->data);
    if (!self) {
        return;
    }
    std::unique_ptr<char[]> ptr{new char[size]};
    auto [it, _] = self->m_reads.emplace(ptr.get(), std::move(ptr));
    buf->base = it->first;
    buf->len = buf->base ? size : 0;
}

void UdpSocket::on_read(uv_udp_t *udp, ssize_t nread, const uv_buf_t *buf, const sockaddr *addr, uint32_t /* flags */) {
    auto *self = (UdpSocket *) Uv<uv_udp_t>::parent_from_data(udp->data);
    if (!self) {
        delete[] buf->base;
        return;
    }

    auto node = self->m_reads.extract(buf->base);

    if (nread == 0 && addr == nullptr) {
        return;
    }

    if (nread < 0) {
        if (nread == UV_EOF) {
            log_sock(self, trace, "EOF");
            self->reset_timeout();
            uv_udp_recv_stop(self->m_udp->raw());

            if (Callbacks cbx = self->get_callbacks(); cbx.on_close != nullptr) {
                cbx.on_close(cbx.arg, {});
            }
            return;
        }
        dbglog(self->m_log, "Read error: {}", uv_strerror(nread));
        return;
    }

    if (Callbacks cbx = self->get_callbacks(); cbx.on_read != nullptr) {
        cbx.on_read(cbx.arg, { (uint8_t *) buf->base, size_t(nread) });
        // Parent may be destroyed inside read.
        return;
    } else {
        // FIXME: dropped read?
        abort();
    }
}

void UdpSocket::reset_timeout() {
    m_current_timeout.reset();
    if (!this->update_timer()) {
        warnlog(m_log, "Failed to update timeout");
    }
}

} // namespace ag::dns
