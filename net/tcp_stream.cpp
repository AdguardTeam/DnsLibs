#include <cassert>
#include <event2/buffer.h>
#include <openssl/err.h>

#include <fmt/std.h>

#include "common/time_utils.h"
#include "common/utils.h"
#include "dns/common/dns_defs.h"

#include "tcp_stream.h"

namespace ag::dns {

#define log_stream(s_, lvl_, fmt_, ...)                                                                                \
    lvl_##log((s_)->m_log, "[id={}] {}(): " fmt_, (s_)->m_id, __func__, ##__VA_ARGS__)

TcpStream::TcpStream(SocketFactory::SocketParameters p, PrepareFdCallback prepare_fd)
        : Socket(__func__, std::move(p), prepare_fd)
{}

std::optional<evutil_socket_t> TcpStream::get_fd() const {
    uv_os_fd_t fd;
    if (0 == uv_fileno((uv_handle_t *) m_tcp->raw(), &fd)) {
        return std::make_optional((evutil_socket_t) fd);
    }
    return std::nullopt;
}

Error<SocketError> TcpStream::connect(ConnectParameters params) {
    log_stream(this, trace, "{}", params.peer);

    const auto *peer = std::get_if<SocketAddress>(&params.peer);
    if (!peer) {
        return make_error(SocketError::AE_INVALID_ARGUMENT, "Peer must be a socket address");
    }

    if (m_connected) {
        assert(0);
        return make_error(SocketError::AE_ALREADY_CONNECTED);
    }

    m_tcp = Uv<uv_tcp_t>::create_with_parent(this);
    if (int err = uv_tcp_init_ex(params.loop->handle(), m_tcp->raw(), (uint8_t)peer->c_sockaddr()->sa_family)) {
        m_tcp->mark_uninit();
        m_tcp.reset();
        auto error = make_error(uv_errno_t(err));
        return make_error(SocketError::AE_SOCK_ERROR, "Failed to create socket", error);
    }

    m_timer = Uv<uv_timer_t>::create_with_parent(this);
    if (int err = uv_timer_init(params.loop->handle(), m_timer->raw())) {
        auto error = make_error(uv_errno_t(err));
        return make_error(SocketError::AE_SOCK_ERROR, "Failed to create timer", error);
    }

    if (uv_os_fd_t fd; m_prepare_fd.func != nullptr && 0 == uv_fileno((uv_handle_t *) m_tcp->raw(), &fd)) {
        if (Error<SocketError> err = m_prepare_fd.func(
                    m_prepare_fd.arg, (evutil_socket_t) fd, *peer, m_parameters.outbound_interface)) {
            return make_error(SocketError::AE_PREPARE_ERROR, AG_FMT("Failed to prepare descriptor: {}", err->str()));
        }
    }

    if (auto e = this->set_callbacks(params.callbacks); e) {
        log_stream(this, dbg, "Failed to set callbacks");
        return e;
    }

    uv_connect_t *req = new uv_connect_t;
    req->data = new UvWeak<uv_tcp_t>(m_tcp);
    Error<SocketError> sock_err;
    if (int err = uv_tcp_connect(req, m_tcp->raw(), peer->c_sockaddr(), on_event)) {
        delete Uv<uv_tcp_t>::weak_from_data(req->data);
        delete req;
        log_stream(this, dbg, "Failed to start connection");
        auto error = make_error(uv_errno_t(err));
        sock_err = (err == UV_ECONNREFUSED)
                ?  make_error(SocketError::AE_CONNECTION_REFUSED, error)
                : make_error(SocketError::AE_SOCK_ERROR, error);
    }

    if (params.timeout.has_value() && !this->set_timeout(params.timeout.value())) {
        return make_error(SocketError::AE_SET_TIMEOUT_ERROR);
    }

    if (sock_err) {
        params.loop->submit([sock_err, weak = m_tcp->weak_from_this()](){
            if (auto tcp = weak.lock()) {
                if (Callbacks cbx = static_cast<TcpStream *>(tcp->parent())->get_callbacks(); cbx.on_close != nullptr) {
                    cbx.on_close(cbx.arg, sock_err);
                }
            }
        });
    }
    return {};
}

struct UvWrite : public uv_write_t {
    Uint8Vector buf;
};

void TcpStream::on_write(uv_write_t *req, int status) {
    delete static_cast<UvWrite *>(req);
}

Error<SocketError> TcpStream::send(Uint8View data) {
    log_stream(this, trace, "{}", data.size());

    auto req = new UvWrite{};
    req->buf.assign(data.begin(), data.begin() + data.size());
    uv_buf_t buf = uv_buf_init((char *) req->buf.data(), req->buf.size());
    if (int err = uv_write(req, (uv_stream_t *) m_tcp->raw(), &buf, 1, &on_write)) {
        log_stream(this, dbg, "Failed to write data");
        return make_error(SocketError::AE_SOCK_ERROR, make_error(uv_errno_t(err)));
    }

    if (!this->update_timer()) {
        return make_error(SocketError::AE_SET_TIMEOUT_ERROR);
    }

    return {};
}

void TcpStream::allocate_read(uv_handle_t *handle, size_t size, uv_buf_t *buf) {
    auto *self = (TcpStream *) Uv<uv_tcp_t>::parent_from_data(handle->data);
    if (!self) {
        return;
    }
    std::unique_ptr<char[]> ptr{new char[size]};
    auto [it, _] = self->m_reads.emplace(ptr.get(), std::move(ptr));
    buf->base = it->first;
    buf->len = buf->base ? size : 0;
}

Error<SocketError> TcpStream::set_callbacks(Callbacks cbx) {
    log_stream(this, trace, "...");

    m_callbacks = cbx;

    update_read_status();

    return {};
}

bool TcpStream::set_timeout(Micros timeout) {
    log_stream(this, trace, "{}", timeout);

    m_current_timeout = timeout;

    return this->update_timer();
}

void TcpStream::reset_timeout() {
    m_current_timeout.reset();
    if (!this->update_timer()) {
        warnlog(m_log, "Failed to update timeout");
    }
}

struct TcpStream::Callbacks TcpStream::get_callbacks() const {
    return m_callbacks;
}

void TcpStream::on_event(uv_connect_t *req, int status) {
    auto *weak_data = Uv<uv_tcp_t>::weak_from_data(req->data);
    auto *self = (TcpStream *) Uv<uv_tcp_t>::parent_from_weak(weak_data);
    delete weak_data;
    delete req;
    if (!self) {
        return;
    }

    if (status == 0) {
        log_stream(self, trace, "Connected");
        if (self->update_timer()) {
            self->m_connected = true;
            self->update_read_status();

            if (Callbacks cbx = self->get_callbacks(); cbx.on_connected != nullptr) {
                cbx.on_connected(cbx.arg);
            }
            return;
        } else {
            log_stream(self, warn, "Failed to set timeout for socket, closing");
        }
    }

    log_stream(self, trace, "Error");
    self->reset_timeout();

    Error<SocketError> error;
    if (status == UV_ETIMEDOUT) {
        error = make_error(SocketError::AE_TIMED_OUT);
    } else if (status == UV_ECONNREFUSED) {
        error = make_error(SocketError::AE_CONNECTION_REFUSED);
    } else {
        error = make_error(SocketError::AE_SOCK_ERROR, make_error(uv_errno_t(status)));
    }
    if (Callbacks cbx = self->get_callbacks(); cbx.on_close != nullptr) {
        cbx.on_close(cbx.arg, error);
    }
}

void TcpStream::on_read(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
    auto *self = (TcpStream *) Uv<uv_tcp_t>::parent_from_data(stream->data);
    if (!self) {
        return;
    }

    if (nread < 0) {
        if (nread == UV_EOF) {
            log_stream(self, trace, "EOF");
            self->reset_timeout();
            uv_read_stop((uv_stream_t *) self->m_tcp->raw());

            if (Callbacks cbx = self->get_callbacks(); cbx.on_close != nullptr) {
                cbx.on_close(cbx.arg, {});
            }
            return;
        }
        dbglog(self->m_log, "Read error: {}", uv_strerror(nread));
        Error<SocketError> err = make_error(SocketError::AE_SOCK_ERROR,
                make_error(uv_errno_t(nread)));
        if (Callbacks cbx = self->get_callbacks(); cbx.on_close != nullptr) {
            cbx.on_close(cbx.arg, err);
        }
        return;
    }

    if (Callbacks cbx = self->get_callbacks(); cbx.on_read != nullptr) {
        auto node = self->m_reads.extract(buf->base);
        cbx.on_read(cbx.arg, { (uint8_t *) node.key(), size_t(nread) });
        // Parent may be destroyed inside read.
        return;
    } else {
        // FIXME: dropped read?
        abort();
    }
}

void TcpStream::on_timeout(uv_timer_t *handle) {
    auto *self = (TcpStream *) Uv<uv_tcp_t>::parent_from_data(handle->data);
    if (!self) {
        return;
    }

    log_stream(self, trace, "Timed out");
    self->reset_timeout();

    auto err = make_error(SocketError::AE_TIMED_OUT);
    if (Callbacks cbx = self->get_callbacks(); cbx.on_close != nullptr) {
        cbx.on_close(cbx.arg, err);
    }
}

bool TcpStream::update_timer() {
    if (m_timer != nullptr) {
        if (m_current_timeout.has_value()) {
            int timeout_ms = ag::to_millis(*m_current_timeout).count();
            return 0 == uv_timer_start(m_timer->raw(), &on_timeout, timeout_ms, 0);
        } else {
            return 0 == uv_timer_stop(m_timer->raw());
        }
    }
    return true;
}

void TcpStream::update_read_status() {
    if (m_tcp != nullptr) {
        if (m_callbacks.on_read != nullptr) {
            uv_read_start((uv_stream_t *) m_tcp->raw(), allocate_read, on_read);
        } else {
            uv_read_stop((uv_stream_t *) m_tcp->raw());
        }
    }
}

TcpStream::~TcpStream() {
    dbglog(m_log, "");
    if (m_tcp) {
        uv_read_stop((uv_stream_t *) m_tcp->raw());
    }
}

} // namespace ag::dns
