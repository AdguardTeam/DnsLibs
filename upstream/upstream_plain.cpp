#include "upstream_plain.h"
#include "common/net_utils.h"
#include "common/utils.h"
#include "net/blocking_socket.h"

#define tracelog_id(l_, pkt_, fmt_, ...) tracelog((l_), "[{}] " fmt_, ldns_pkt_id(pkt_), ##__VA_ARGS__)

using std::chrono::duration_cast;

namespace ag {

TcpPool::TcpPool(EventLoopPtr loop, const SocketAddress &address, PlainUpstream *upstream)
        : DnsFramedPool(std::move(loop), upstream)
        , m_address(address) {
}

static SocketAddress prepare_address(const std::string &address_string) {
    auto address = ag::utils::str_to_socket_address(address_string);
    if (address.port() == 0) {
        return SocketAddress(address.addr(), PlainUpstream::DEFAULT_PORT);
    }
    return address;
}

PlainUpstream::PlainUpstream(const UpstreamOptions &opts, const UpstreamFactoryConfig &config)
        : Upstream(opts, config)
        , m_log(AG_FMT("Plain upstream ({})", opts.address))
        , m_prefer_tcp(utils::starts_with(opts.address, TCP_SCHEME))
        , m_pool(EventLoop::create(),
                  prepare_address(m_prefer_tcp ? opts.address.substr(TCP_SCHEME.length()) : opts.address), this) {
}

ErrString PlainUpstream::init() {
    if (!m_pool.address().valid()) {
        return AG_FMT("Passed server address is not valid: {}", m_options.address);
    }

    return std::nullopt;
}

PlainUpstream::ExchangeResult PlainUpstream::exchange(ldns_pkt *request_pkt, const DnsMessageInfo *info) {
    ldns_buffer_ptr buffer{ldns_buffer_new(REQUEST_BUFFER_INITIAL_CAPACITY)};
    ldns_status status = ldns_pkt2buffer_wire(&*buffer, request_pkt);
    if (status != LDNS_STATUS_OK) {
        return {nullptr, ldns_get_errorstr_by_id(status)};
    }

    ldns_rr *question = ldns_rr_list_rr(ldns_pkt_question(request_pkt), 0);
    AllocatedPtr<char> domain;
    if (question) {
        domain = AllocatedPtr<char>(ldns_rdf2str(ldns_rr_owner(question)));
        tracelog_id(m_log, request_pkt, "Querying for a domain: {}", domain.get());
    }

    utils::Timer timer;
    Millis timeout = m_options.timeout;

    if (!m_prefer_tcp && !(info && info->proto == utils::TP_TCP)) {
        BlockingSocket socket(this->make_socket(utils::TP_UDP));
        if (!socket) {
            return {nullptr, "Can't initialize blocking socket wrapper"};
        }

        if (auto e = socket.connect({m_pool.address(), timeout}); e.has_value()) {
            return {nullptr,
                    (e->code == utils::AG_ETIMEDOUT) // To cancel second retry of exchange
                            ? std::string(TIMEOUT_STR)
                            : std::move(e->description)};
        }

        timeout -= timer.elapsed<decltype(timeout)>();
        if (timeout.count() <= 0) {
            return {nullptr, std::string(TIMEOUT_STR)};
        }
        timer.reset();

        if (auto e = socket.send_dns_packet(
                    {(uint8_t *) ldns_buffer_begin(buffer.get()), ldns_buffer_position(buffer.get())});
                e.has_value()) {
            return {nullptr, std::move(e->description)};
        }

        auto r = socket.receive_dns_packet(timeout);
        if (auto *e = std::get_if<Socket::Error>(&r); e != nullptr) {
            return {nullptr,
                    (e->code == utils::AG_ETIMEDOUT) // To cancel second retry of exchange
                            ? std::string(TIMEOUT_STR)
                            : std::move(e->description)};
        }

        auto &reply = std::get<Uint8Vector>(r);
        ldns_pkt *reply_pkt = nullptr;
        status = ldns_wire2pkt(&reply_pkt, reply.data(), reply.size());
        if (status != LDNS_STATUS_OK) {
            return {nullptr, ldns_get_errorstr_by_id(status)};
        }
        // If not truncated, return result. Otherwise, try TCP.
        if (!ldns_pkt_tc(reply_pkt)) {
            return {ldns_pkt_ptr(reply_pkt), std::nullopt};
        }
        ldns_pkt_free(reply_pkt);
    }

    timeout -= timer.elapsed<decltype(timeout)>();
    if (timeout.count() <= 0) {
        return {nullptr, std::string(TIMEOUT_STR)};
    }

    // TCP request
    Uint8View buf{ldns_buffer_begin(buffer.get()), ldns_buffer_position(buffer.get())};
    tracelog_id(m_log, request_pkt, "Sending TCP request for a domain: {}", domain ? domain.get() : "(unknown)");
    Connection::ReadResult result = m_pool.perform_request(buf, timeout);
    if (result.error.has_value()) {
        return {nullptr, std::move(result.error)};
    }

    const Uint8Vector &reply = result.reply;
    ldns_pkt *reply_pkt = nullptr;
    status = ldns_wire2pkt(&reply_pkt, reply.data(), reply.size());
    if (status != LDNS_STATUS_OK) {
        return {nullptr, ldns_get_errorstr_by_id(status)};
    }
    return {ldns_pkt_ptr(reply_pkt), std::nullopt};
}

ConnectionPool::GetResult TcpPool::get() {
    std::scoped_lock l(m_mutex);
    if (!m_connections.empty()) {
        return {*m_connections.begin(), Secs(0), std::nullopt};
    }
    return create();
}

ConnectionPool::GetResult TcpPool::create() {
    ConnectionPtr connection = create_connection(m_address, std::nullopt);
    add_pending_connection(connection);
    return {std::move(connection), Secs(0), std::nullopt};
}

const SocketAddress &TcpPool::address() const {
    return m_address;
}

} // namespace ag
