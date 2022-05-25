#include "net/blocking_socket.h"
#include "net/tcp_dns_buffer.h"
#include <atomic>

#define log_sock(s_, lvl_, fmt_, ...) lvl_##log((s_)->m_log, "[id={}] {}(): " fmt_, (s_)->m_id, __func__, ##__VA_ARGS__)

namespace ag {

using namespace std::chrono;

static std::atomic_size_t next_id = {0};

BlockingSocket::BlockingSocket(SocketFactory::SocketPtr socket)
        : m_log(__func__)
        , m_id(next_id.fetch_add(1, std::memory_order::memory_order_relaxed))
        , m_underlying_socket(std::move(socket)) {
}

BlockingSocket::~BlockingSocket() {
    // the underlying socket must be closed before the event loop
    m_underlying_socket.reset();
    // run again in case the loop was stopped and it has some unfinished task for the socket
    m_event_loop->start();
    m_event_loop.reset();
}

std::optional<Socket::Error> BlockingSocket::connect(ConnectParameters params) {
    log_sock(this, trace, "{}", params.peer.str());

    if (auto e = m_underlying_socket->connect(this->make_underlying_connect_parameters(params)); e.has_value()) {
        return e;
    }

    m_event_loop->start();
    m_event_loop->join();

    return std::exchange(m_pending_error, std::nullopt);
}

std::optional<Socket::Error> BlockingSocket::send(Uint8View data) {
    log_sock(this, trace, "{}", data.size());
    return m_underlying_socket->send(data);
}

std::optional<Socket::Error> BlockingSocket::send_dns_packet(Uint8View data) {
    log_sock(this, trace, "{}", data.size());
    return m_underlying_socket->send_dns_packet(data);
}

std::optional<Socket::Error> BlockingSocket::receive(
        struct OnReadCallback on_read_handler, std::optional<microseconds> timeout) {
    log_sock(this, trace, "...");

    m_on_read_callback = on_read_handler;
    if (auto e = m_underlying_socket->set_callbacks({on_connected, on_read, on_close, (void *) this}); e.has_value()) {
        return e;
    }

    if (timeout.has_value() && !m_underlying_socket->set_timeout(timeout.value())) {
        return {{-1, "Failed to set time out"}};
    }

    m_event_loop->start();
    m_event_loop->join();

    return std::exchange(m_pending_error, std::nullopt);
}

BlockingSocket::ReceiveDnsPacketResult BlockingSocket::receive_dns_packet(std::optional<microseconds> timeout) {
    ReceiveDnsPacketResult result;

    struct read_context {
        utils::TransportProtocol protocol;
        TcpDnsBuffer tcp_buffer;
        Uint8Vector reply;
    };

    constexpr auto on_read = [](void *arg, Uint8View data) {
        auto *ctx = (read_context *) arg;
        bool done = false;
        switch (ctx->protocol) {
        case utils::TransportProtocol::TP_TCP:
            ctx->tcp_buffer.store(data);
            if (auto p = ctx->tcp_buffer.extract_packet(); p.has_value()) {
                ctx->reply = std::move(p.value());
                done = true;
            }
            break;
        case utils::TransportProtocol::TP_UDP:
            ctx->reply = {data.begin(), data.end()};
            done = true;
            break;
        }
        return !done;
    };

    read_context context = {m_underlying_socket->get_protocol()};
    struct OnReadCallback on_read_handler = {on_read, &context};

    if (auto e = this->receive(on_read_handler, timeout); e.has_value()) {
        return e.value();
    }

    return std::move(context.reply);
}

Socket::ConnectParameters BlockingSocket::make_underlying_connect_parameters(ConnectParameters &params) const {
    return {
            m_event_loop.get(),
            params.peer,
            {on_connected, nullptr, on_close, (void *) this},
            params.timeout,
    };
}

void BlockingSocket::on_connected(void *arg) {
    auto *self = (BlockingSocket *) arg;
    log_sock(self, trace, "...");
    self->m_event_loop->stop();
}

void BlockingSocket::on_read(void *arg, Uint8View data) {
    auto *self = (BlockingSocket *) arg;
    log_sock(self, trace, "{}", data.size());
    if (!self->m_on_read_callback.func(self->m_on_read_callback.arg, data)) {
        self->m_event_loop->stop();
    }
}

void BlockingSocket::on_close(void *arg, std::optional<Socket::Error> error) {
    auto *self = (BlockingSocket *) arg;
    if (error.has_value()) {
        log_sock(self, trace, "{} ({})", error->description, error->code);
        self->m_pending_error = std::move(error);
    }
    self->m_event_loop->stop();
}

} // namespace ag
