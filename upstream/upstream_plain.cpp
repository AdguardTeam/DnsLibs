#include "upstream_plain.h"
#include "common/net_utils.h"
#include "common/utils.h"
#include "dns/net/aio_socket.h"
#include "dns/net/utils.h"

#define tracelog_id(l_, pkt_, fmt_, ...) tracelog((l_), "[{}] " fmt_, ldns_pkt_id(pkt_), ##__VA_ARGS__)

using std::chrono::duration_cast;

namespace ag::dns {

static SocketAddress prepare_address(std::string_view address_string) {
    if (utils::starts_with(address_string, PlainUpstream::TCP_SCHEME)) {
        address_string.remove_prefix(PlainUpstream::TCP_SCHEME.size());
    }
    auto address = ag::utils::str_to_socket_address(address_string);
    if (address.port() == 0) {
        return SocketAddress(address.addr(), DEFAULT_PLAIN_PORT);
    }
    return address;
}

PlainUpstream::PlainUpstream(const UpstreamOptions &opts, const UpstreamFactoryConfig &config)
        : Upstream(opts, config)
        , m_log(AG_FMT("Plain upstream ({})", opts.address))
        , m_prefer_tcp(utils::starts_with(opts.address, TCP_SCHEME))
        , m_address(prepare_address(opts.address))
        , m_shutdown_guard(std::make_shared<bool>(true))
{

}

Error<Upstream::InitError> PlainUpstream::init() {
    if (!m_address.valid()) {
        return make_error(InitError::AE_INVALID_ADDRESS, m_options.address);
    }

    m_pool = std::make_shared<ConnectionPool<DnsFramedConnection>>(config().loop, shared_from_this(), 10);

    return {};
}

coro::Task<Upstream::ExchangeResult> PlainUpstream::exchange(const ldns_pkt *request_pkt, const DnsMessageInfo *info) {
    std::weak_ptr<bool> guard = m_shutdown_guard;

    ldns_buffer_ptr buffer{ldns_buffer_new(REQUEST_BUFFER_INITIAL_CAPACITY)};
    ldns_status status = ldns_pkt2buffer_wire(&*buffer, request_pkt);
    if (status != LDNS_STATUS_OK) {
        co_return make_error(DnsError::AE_ENCODE_ERROR, ldns_get_errorstr_by_id(status));
    }

    ldns_rr *question = ldns_rr_list_rr(ldns_pkt_question(request_pkt), 0);
    AllocatedPtr<char> domain;
    if (question) {
        domain = AllocatedPtr<char>(ldns_rdf2str(ldns_rr_owner(question)));
        tracelog_id(m_log, request_pkt, "Querying for a domain: {}", domain.get());
    }

    utils::Timer timer;
    Millis timeout = m_config.timeout;

    if (!m_prefer_tcp && !(info && info->proto == utils::TP_TCP)) {
        AioSocket socket(this->make_socket(utils::TP_UDP));
        auto err = co_await socket.connect({&m_config.loop, m_address, timeout});
        if (guard.expired()) {
            co_return make_error(DnsError::AE_SHUTTING_DOWN);
        }
        if (err) {
            co_return (err->value() == SocketError::AE_TIMED_OUT) // To cancel second retry of exchange
                            ? make_error(DnsError::AE_TIMED_OUT, "Timed out while connecting to remote host via UDP")
                            : make_error(DnsError::AE_SOCKET_ERROR, err);
        }

        timeout -= timer.elapsed<decltype(timeout)>();
        if (timeout.count() <= 0) {
            co_return make_error(DnsError::AE_TIMED_OUT, "Timed out after connecting to remote host");
        }
        timer.reset();

        if (auto err = send_dns_packet(&socket, {(uint8_t *) ldns_buffer_begin(buffer.get()), ldns_buffer_position(buffer.get())})) {
            co_return make_error(DnsError::AE_SOCKET_ERROR, err);
        }

        auto r = co_await receive_dns_packet(&socket, timeout);
        if (guard.expired()) {
            co_return make_error(DnsError::AE_SHUTTING_DOWN);
        }
        if (r.has_error()) {
            co_return (r.error()->value() == SocketError::AE_TIMED_OUT) // To cancel second retry of exchange
                    ? make_error(DnsError::AE_TIMED_OUT, "Timed out while waiting for DNS reply via UDP")
                    : make_error(DnsError::AE_SOCKET_ERROR, r.error());
        }

        auto &reply = r.value();
        ldns_pkt *reply_pkt = nullptr;
        status = ldns_wire2pkt(&reply_pkt, reply.data(), reply.size());
        if (status != LDNS_STATUS_OK) {
            co_return make_error(DnsError::AE_DECODE_ERROR, ldns_get_errorstr_by_id(status));
        }
        // If not truncated, return result. Otherwise, try TCP.
        if (!ldns_pkt_tc(reply_pkt)) {
            co_return ldns_pkt_ptr{reply_pkt};
        }
        ldns_pkt_free(reply_pkt);
    }

    timeout -= timer.elapsed<decltype(timeout)>();
    if (timeout.count() <= 0) {
        co_return make_error(DnsError::AE_TIMED_OUT, "TCP request should be done but no time left");
    }

    // TCP request
    Uint8View buf{ldns_buffer_begin(buffer.get()), ldns_buffer_position(buffer.get())};
    tracelog_id(m_log, request_pkt, "Sending TCP request for a domain: {}", domain ? domain.get() : "(unknown)");
    auto result = co_await m_pool->perform_request(buf, timeout);
    if (guard.expired()) {
        co_return make_error(DnsError::AE_SHUTTING_DOWN);
    }
    if (result.has_error()) {
        co_return result.error();
    }

    const Uint8Vector &reply = result.value();
    ldns_pkt *reply_pkt = nullptr;
    status = ldns_wire2pkt(&reply_pkt, reply.data(), reply.size());
    if (status != LDNS_STATUS_OK) {
        co_return make_error(DnsError::AE_DECODE_ERROR, ldns_get_errorstr_by_id(status));
    }
    co_return ldns_pkt_ptr{reply_pkt};
}

} // namespace ag::dns
