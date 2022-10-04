#include <ldns/error.h>
#include <ldns/net.h>

#include "common/net_utils.h"
#include "common/utils.h"
#include "dns/common/dns_defs.h"
#include "dns/common/net_consts.h"
#include "dns/dnscrypt/dns_crypt_ldns.h"
#include "dns/net/aio_socket.h"

namespace ag::dns::dnscrypt {

ldns_pkt_ptr create_request_ldns_pkt(ldns_rr_type rr_type, ldns_rr_class rr_class, uint16_t flags,
        std::string_view dname_str, std::optional<size_t> size_opt) {
    ldns_rdf *dname = ldns_dname_new_frm_str(std::string(dname_str).c_str());
    if (!dname) {
        return nullptr;
    }
    ldns_pkt_ptr pkt(ldns_pkt_query_new(dname, rr_type, rr_class, flags));
    if (!pkt) {
        std::free(dname);
        return nullptr;
    }
    if (size_opt) {
        ldns_pkt_set_size(pkt.get(), *size_opt);
    }
    return pkt;
}

LdnsEncodeResult create_ldns_buffer(const ldns_pkt &request_pkt) {
    ldns_buffer_ptr result(ldns_buffer_new(REQUEST_BUFFER_INITIAL_CAPACITY));
    ldns_status status = ldns_pkt2buffer_wire(result.get(), &request_pkt);
    if (status != LDNS_STATUS_OK) {
        return make_error(DnsError::AE_ENCODE_ERROR, ldns_get_errorstr_by_id(status));
    }
    return result;
}

LdnsDecodeResult create_ldns_pkt(uint8_t *data, size_t size) {
    ldns_pkt *pkt = nullptr;
    ldns_status status = ldns_wire2pkt(&pkt, data, size);
    ldns_pkt_ptr result(pkt);
    if (status != LDNS_STATUS_OK) {
        return make_error(DnsError::AE_DECODE_ERROR, ldns_get_errorstr_by_id(status));
    }
    return result;
}

coro::Task<DnsExchangeUnparsedResult> dns_exchange(EventLoop &loop, Millis timeout, const SocketAddress &socket_address, ldns_buffer &buffer,
        const SocketFactory *socket_factory, SocketFactory::SocketParameters socket_parameters) {

    utils::Timer timer;

    AioSocket socket(socket_factory->make_socket(std::move(socket_parameters)));
    if (auto err = co_await socket.connect({&loop, socket_address, timeout})) {
        co_return {.error = make_error(DnsError::AE_SOCKET_ERROR, err)};
    }

    timeout -= timer.elapsed<decltype(timeout)>();
    if (timeout <= decltype(timeout)(0)) {
        co_return {.error = make_error(DnsError::AE_TIMED_OUT)};
    }

    if (auto err = socket.send_dns_packet({(uint8_t *) ldns_buffer_begin(&buffer), ldns_buffer_position(&buffer)})) {
        co_return {.error = make_error(DnsError::AE_SOCKET_ERROR, err)};
    }

    auto r = co_await socket.receive_dns_packet(timeout);
    if (r.has_error()) {
        co_return {.error = make_error(DnsError::AE_SOCKET_ERROR, r.error())};
    }

    auto &reply = r.value();
    co_return {std::move(reply), timer.elapsed<Millis>()};
}

coro::Task<DnsExchangeResult> dns_exchange_from_ldns_pkt(EventLoop &loop, Millis timeout, const SocketAddress &socket_address,
        const ldns_pkt &request_pkt, const SocketFactory *socket_factory,
        SocketFactory::SocketParameters socket_parameters) {

    auto buffer = create_ldns_buffer(request_pkt);
    if (buffer.has_error()) {
        co_return {.error = buffer.error()};
    }
    auto [reply, rtt, allocated_err]
            = co_await dns_exchange(loop, timeout, socket_address, *buffer.value(), socket_factory, std::move(socket_parameters));
    if (allocated_err) {
        co_return {.error = allocated_err};
    }
    auto reply_pkt = create_ldns_pkt(reply.data(), reply.size());
    if (reply_pkt.has_error()) {
        co_return {.error = reply_pkt.error()};
    }
    if (ldns_pkt_tc(reply_pkt->get())) {
        co_return {.error = make_error(DnsError::AE_TRUNCATED_RESPONSE)};
    }
    co_return {std::move(reply_pkt.value()), rtt, {}};
}

} // namespace ag::dns::dnscrypt
