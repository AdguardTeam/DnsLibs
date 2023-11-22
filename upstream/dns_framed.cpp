#include <memory>
#include <vector>
#include <string>
#include <cassert>
#include <memory>
#include <ldns/wire2host.h>

#include "common/socket_address.h"
#include "common/logger.h"
#include "common/utils.h"
#include "dns/net/socket.h"
#include "dns/net/tcp_dns_buffer.h"
#include "dns/net/utils.h"

#include "dns_framed.h"

#define log_conn(l_, lvl_, conn_, fmt_, ...) lvl_##log(l_, "[id={} addr={}] " fmt_, conn_->m_id, conn_->address_str(), ##__VA_ARGS__)


using namespace std::chrono;

namespace ag::dns {

static constexpr int DEFAULT_PORT = 53;
static const std::string TCP_SCHEME = "tcp://";

std::atomic<uint16_t> DnsFramedConnection::m_next_request_id;

static SocketAddress prepare_address(std::string_view address_string) {
    if (utils::starts_with(address_string, TCP_SCHEME)) {
        address_string.remove_prefix(TCP_SCHEME.size());
    }
    auto address = ag::utils::str_to_socket_address(address_string);
    if (address.port() == 0) {
        return SocketAddress(address.addr(), DEFAULT_PORT);
    }
    return address;
}

DnsFramedConnection::DnsFramedConnection(
        const ConstructorAccess &access, EventLoop &loop, const ConnectionPoolPtr &pool, const std::string &address_str)
        : Connection(access, loop, pool, address_str)
        , m_log(__func__)
        , m_idle_timeout(std::chrono::seconds(30)) {
}

void DnsFramedConnection::connect() {
    assert(m_state == Connection::Status::IDLE);
    m_state = Connection::Status::PENDING;
    Upstream *upstream = m_pool.lock()->upstream();
    assert(upstream != nullptr);
    m_stream = upstream->make_socket(utils::TP_TCP);
    auto err = m_stream->connect({
                                         &m_loop,
                                         prepare_address(upstream->options().address),
                                         { on_connected, on_read, on_close, this },
                                         upstream->config().timeout,
                                 });
    if (err) {
        log_conn(m_log, err, this, "Failed to start connect: {}", err->str());
        on_close(this, err);
    }
}

DnsFramedConnection::~DnsFramedConnection() {
    m_stream.reset();
    std::vector<uint16_t> request_ids;
    for (auto node : m_requests) {
        request_ids.push_back(node.first);
    }
    for (auto request_id : request_ids) {
        this->finish_request(request_id, make_error(DnsError::AE_SHUTTING_DOWN));
    }
}

void DnsFramedConnection::on_connected(void *arg) {
    auto *self = (DnsFramedConnection *)arg;
    log_conn(self->m_log, trace, self, "{}", __func__);
    DnsFramedConnectionPtr ptr = self->shared_from_this();

    if (self->m_state == Status::CLOSED) {
        log_conn(self->m_log, trace, self, "Already closed");
        return;
    }
    assert(self->m_state == Status::PENDING);
    self->m_state = Status::ACTIVE;
    if (self->m_idle_timeout.count()) {
        self->m_stream->set_timeout(self->m_idle_timeout);
    }
    std::vector<uint16_t> request_ids;
    for (auto node : self->m_requests) {
        request_ids.push_back(node.first);
    }
    for (auto request_id : request_ids) {
        self->resume_request(request_id);
    }
    log_conn(self->m_log, trace, self, "{} finished", __func__);
}

void DnsFramedConnection::on_read(void *arg, Uint8View data) {
    auto *self = (DnsFramedConnection *)arg;
    log_conn(self->m_log, trace, self, "{}", __func__);
    DnsFramedConnectionPtr ptr = self->shared_from_this();

    if (self->m_state == Status::CLOSED) {
        log_conn(self->m_log, trace, self, "Already closed");
        return;
    }
    assert(self->m_state == Status::ACTIVE);

    while (!data.empty()) {
        data = self->m_input_buffer.store(data);

        std::optional<std::vector<uint8_t>> packet = self->m_input_buffer.extract_packet();
        if (!packet.has_value()) {
            return;
        }

        int id = ntohs(*(uint16_t *) packet->data());
        log_conn(self->m_log, trace, self, "Got response for {}", id);
        log_conn(self->m_log, trace, self, "m_requests size: {}", self->m_requests.size());
        for (auto &tuple : self->m_requests) {
            log_conn(self->m_log, trace, self, "dumped request id: {}", tuple.first);
        }

        self->finish_request(id, Reply{std::move(packet.value())});
    }

    log_conn(self->m_log, trace, self, "{} finished", __func__);
}

void DnsFramedConnection::on_close(void *arg, Error<SocketError> error) {
    auto *self = (DnsFramedConnection *)arg;

    Error<DnsError> err;
    if (error) {
        err = make_error(DnsError::AE_SOCKET_ERROR, error);
    } else {
        err = make_error(DnsError::AE_CONNECTION_CLOSED);
    }
    self->on_close(err);
}

void DnsFramedConnection::on_close(Error<DnsError> dns_error) {
    DnsFramedConnectionPtr ptr = shared_from_this();
    log_conn(m_log, trace, this, "{}", __func__);

    if (m_state == Status::CLOSED) {
        log_conn(m_log, trace, this, "Already closed");
        return;
    }

    if (dns_error->value() != DnsError::AE_CONNECTION_CLOSED) {
        log_conn(m_log, trace, this, "{} error {}", __func__, dns_error->str());
    }

    m_state = Status::CLOSED;
    std::vector<uint16_t> request_ids;
    for (auto node : m_requests) {
        request_ids.push_back(node.first);
    }
    for (auto request_id : request_ids) {
        this->finish_request(request_id, dns_error);
    }

    if (auto *pool = m_pool.lock().get()) {
        pool->remove_connection(ptr);
    }
    log_conn(m_log, trace, this, "{} finished", __func__);
}

coro::Task<Connection::Reply> DnsFramedConnection::perform_request(Uint8View packet, Millis timeout) {
    if (packet.size() < 2) {
        co_return Reply(make_error(DnsError::AE_REQUEST_PACKET_TOO_SHORT));
    }

    auto guard = weak_from_this();
    Uint8Vector request_to_send{packet.begin(), packet.end()};
    uint16_t request_id = m_next_request_id++;
    Request request{};
    utils::Timer timer;
    request.request_id = request_id;
    request.original_request_id = ntohs(*(uint16_t *) request_to_send.data());
    *(uint16_t *) request_to_send.data() = htons(request_id);
    request.parent = this;

    request.timeout = std::max(Millis{0}, timeout - timer.elapsed<Millis>());
    co_await ensure_connected(&request);
    if (guard.expired()) {
        co_return Reply(make_error(DnsError::AE_SHUTTING_DOWN));
    }
    if (request.reply) {
        co_return request.reply.value();
    }

    assert(m_state == Connection::Status::ACTIVE);

    auto socket_error = send_dns_packet(m_stream.get(), {request_to_send.data(), request_to_send.size()});
    if (socket_error) {
        infolog(m_log, "Error sending :(");
        co_return make_error(DnsError::AE_SOCKET_ERROR, std::move(socket_error));
    }

    request.timeout = std::max(Millis{0}, timeout - timer.elapsed<Millis>());
    co_await wait_response(&request);
    if (guard.expired()) {
        co_return Reply(make_error(DnsError::AE_SHUTTING_DOWN));
    }

    Reply &reply = request.reply.value();

    if (reply.has_value() && reply.value().size() >= 2) {
        *(uint16_t *) reply.value().data() = htons(request.original_request_id);
    }

    co_return request.reply.value();
}

void DnsFramedConnection::resume_request(uint16_t request_id) {
    auto node = m_requests.extract(request_id);
    if (node.empty()) {
        return;
    }
    node.mapped()->caller.resume();
}

void DnsFramedConnection::finish_request(uint16_t request_id, Reply &&reply) {
    auto node = m_requests.extract(request_id);
    if (node.empty()) {
        return;
    }
    node.mapped()->reply = std::move(reply);
    node.mapped()->complete();
}

} // namespace ag::dns
