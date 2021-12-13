#include <ag_blocking_socket.h>
#include <ag_tcp_dns_buffer.h>
#include <atomic>


#define log_sock(s_, lvl_, fmt_, ...) lvl_##log((s_)->log, "[id={}] {}(): " fmt_, (s_)->id, __func__, ##__VA_ARGS__)


using namespace ag;
using namespace std::chrono;


static std::atomic_size_t next_id = { 0 };


blocking_socket::blocking_socket(socket_factory::socket_ptr socket)
    : log(__func__)
    , id(next_id.fetch_add(1, std::memory_order::memory_order_relaxed))
    , underlying_socket(std::move(socket))
{}

blocking_socket::~blocking_socket() {
    // the underlying socket must be closed before the event loop
    this->underlying_socket.reset();
    // run again in case the loop was stopped and it has some unfinished task for the socket
    this->event_loop->start();
    this->event_loop.reset();
}

std::optional<socket::error> blocking_socket::connect(connect_parameters params) {
    log_sock(this, trace, "{}", params.peer.str());

    if (auto e = this->underlying_socket->connect(this->make_underlying_connect_parameters(params));
            e.has_value()) {
        return e;
    }

    this->event_loop->start();
    this->event_loop->join();

    return std::exchange(this->pending_error, std::nullopt);
}

std::optional<socket::error> blocking_socket::send(Uint8View data) {
    log_sock(this, trace, "{}", data.size());
    return this->underlying_socket->send(data);
}

std::optional<socket::error> blocking_socket::send_dns_packet(Uint8View data) {
    log_sock(this, trace, "{}", data.size());
    return this->underlying_socket->send_dns_packet(data);
}

std::optional<socket::error> blocking_socket::receive(struct on_read_callback on_read_handler,
        std::optional<microseconds> timeout) {
    log_sock(this, trace, "...");

    this->on_read_callback = on_read_handler;
    if (auto e = this->underlying_socket->set_callbacks({ on_connected, on_read, on_close, (void *)this });
            e.has_value()) {
        return e;
    }

    if (timeout.has_value() && !this->underlying_socket->set_timeout(timeout.value())) {
        return { { -1, "Failed to set time out" } };
    }

    this->event_loop->start();
    this->event_loop->join();

    return std::exchange(this->pending_error, std::nullopt);
}

blocking_socket::receive_dns_packet_result blocking_socket::receive_dns_packet(std::optional<microseconds> timeout) {
    receive_dns_packet_result result;

    struct read_context {
        utils::transport_protocol protocol;
        tcp_dns_buffer tcp_buffer;
        std::vector<uint8_t> reply;
    };

    constexpr auto on_read =
            [] (void *arg, Uint8View data) {
                auto *ctx = (read_context *)arg;
                bool done = false;
                switch (ctx->protocol) {
                case utils::transport_protocol::TP_TCP:
                    ctx->tcp_buffer.store(data);
                    if (auto p = ctx->tcp_buffer.extract_packet(); p.has_value()) {
                        ctx->reply = std::move(p.value());
                        done = true;
                    }
                    break;
                case utils::transport_protocol::TP_UDP:
                    ctx->reply = { data.begin(), data.end() };
                    done = true;
                    break;
                }
                return !done;
            };

    read_context context = { this->underlying_socket->get_protocol() };
    struct on_read_callback on_read_handler = { on_read, &context };

    if (auto e = this->receive(on_read_handler, timeout); e.has_value()) {
        return e.value();
    }

    return std::move(context.reply);
}


socket::connect_parameters blocking_socket::make_underlying_connect_parameters(
        connect_parameters &params) const {
    return {
            this->event_loop.get(),
            params.peer,
            { on_connected, nullptr, on_close, (void *)this },
            params.timeout,
    };
}

void blocking_socket::on_connected(void *arg) {
    auto *self = (blocking_socket *)arg;
    log_sock(self, trace, "...");
    self->event_loop->stop();
}

void blocking_socket::on_read(void *arg, Uint8View data) {
    auto *self = (blocking_socket *)arg;
    log_sock(self, trace, "{}", data.size());
    if (!self->on_read_callback.func(self->on_read_callback.arg, data)) {
        self->event_loop->stop();
    }
}

void blocking_socket::on_close(void *arg, std::optional<socket::error> error) {
    auto *self = (blocking_socket *)arg;
    if (error.has_value()) {
        log_sock(self, trace, "{} ({})", error->description, error->code);
        self->pending_error = std::move(error);
    }
    self->event_loop->stop();
}
