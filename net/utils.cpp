#ifndef _WIN32
#include <netinet/in.h>
#else
#include <Winsock2.h>
#endif

#include "dns/net/tcp_dns_buffer.h"
#include "dns/net/utils.h"

namespace ag {

Error<dns::SocketError> dns::send_dns_packet(Socket *self, Uint8View data) {
    Error<SocketError> err;

    switch (self->get_protocol()) {
    case utils::TP_UDP:
        err = self->send(data);
        break;
    case utils::TP_TCP: {
        uint16_t length = htons(data.size());

        std::vector<uint8_t> buffer(sizeof(length) + data.size());
        memcpy(buffer.data(), (uint8_t *) &length, sizeof(length));
        memcpy(buffer.data() + sizeof(length), data.data(), data.size());

        err = self->send({buffer.data(), buffer.size()});
        break;
    }
    }

    return err;
}

Error<dns::SocketError> dns::send_dns_packet(AioSocket *self, Uint8View data) {
    return send_dns_packet(self->get_underlying(), data);
}

coro::Task<Result<Uint8Vector, dns::SocketError>> dns::receive_dns_packet(
        AioSocket *self, std::optional<Micros> timeout) {
    struct ReadContext {
        utils::TransportProtocol protocol;
        TcpDnsBuffer tcp_buffer;
        Uint8Vector reply;
    };

    constexpr auto on_read = [](void *arg, Uint8View data) { // NOLINT(readability-identifier-naming)
        auto *ctx = (ReadContext *) arg;
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

    ReadContext context = {
            .protocol = self->get_underlying()->get_protocol(),
    };
    AioSocket::OnReadCallback on_read_handler = {on_read, &context};

    if (auto err = co_await self->receive(on_read_handler, timeout)) {
        co_return err;
    }

    co_return std::move(context.reply);
}

} // namespace ag
