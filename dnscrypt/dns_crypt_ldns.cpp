#include <ldns/error.h>
#include <ldns/net.h>

#include "common/net_consts.h"
#include "common/net_utils.h"
#include "common/utils.h"
#include "dnscrypt/dns_crypt_ldns.h"
#include "net/blocking_socket.h"

namespace ag::dnscrypt {

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

CreateLdnsBufferResult create_ldns_buffer(const ldns_pkt &request_pkt) {
    static constexpr utils::MakeError<CreateLdnsBufferResult> make_error;
    ldns_buffer_ptr result(ldns_buffer_new(REQUEST_BUFFER_INITIAL_CAPACITY));
    ldns_status status = ldns_pkt2buffer_wire(result.get(), &request_pkt);
    if (status != LDNS_STATUS_OK) {
        return make_error(ldns_get_errorstr_by_id(status));
    }
    return {std::move(result), std::nullopt};
}

CreateLdnsPktResult create_ldns_pkt(uint8_t *data, size_t size) {
    static constexpr utils::MakeError<CreateLdnsPktResult> make_error;
    ldns_pkt *pkt = nullptr;
    ldns_status status = ldns_wire2pkt(&pkt, data, size);
    ldns_pkt_ptr result(pkt);
    if (status != LDNS_STATUS_OK) {
        return make_error(ldns_get_errorstr_by_id(status));
    }
    return {std::move(result), std::nullopt};
}

DnsExchangeUnparsedResult dns_exchange(Millis timeout, const SocketAddress &socket_address, ldns_buffer &buffer,
        const SocketFactory *socket_factory, SocketFactory::SocketParameters socket_parameters) {
    static constexpr utils::MakeError<DnsExchangeUnparsedResult> make_error;

    utils::Timer timer;

    BlockingSocket socket(socket_factory->make_socket(std::move(socket_parameters)));
    if (!socket) {
        return make_error("Can't initialize blocking socket wrapper");
    }
    if (auto e = socket.connect({socket_address, timeout}); e.has_value()) {
        return make_error(std::move(e->description));
    }

    timeout -= timer.elapsed<decltype(timeout)>();
    if (timeout <= decltype(timeout)(0)) {
        return make_error(evutil_socket_error_to_string(utils::AG_ETIMEDOUT));
    }

    if (auto e = socket.send_dns_packet({(uint8_t *) ldns_buffer_begin(&buffer), ldns_buffer_position(&buffer)});
            e.has_value()) {
        return make_error(std::move(e->description));
    }

    auto r = socket.receive_dns_packet(timeout);
    if (auto *e = std::get_if<Socket::Error>(&r); e != nullptr) {
        return make_error(std::move(e->description));
    }

    auto &reply = std::get<Uint8Vector>(r);
    return {std::move(reply), timer.elapsed<Millis>()};
}

DnsExchangeResult dns_exchange_from_ldns_buffer(Millis timeout, const SocketAddress &socket_address,
        ldns_buffer &buffer, const SocketFactory *socket_factory, SocketFactory::SocketParameters socket_parameters) {
    static constexpr utils::MakeError<DnsExchangeResult> make_error;
    auto [reply, rtt, allocated_err]
            = dns_exchange(timeout, socket_address, buffer, socket_factory, std::move(socket_parameters));
    if (allocated_err) {
        return make_error(std::move(allocated_err));
    }
    auto [reply_pkt_unique_ptr, reply_err] = create_ldns_pkt(reply.data(), reply.size());
    if (reply_err) {
        return make_error(std::move(reply_err));
    }
    if (ldns_pkt_tc(reply_pkt_unique_ptr.get())) {
        return make_error("Truncated response");
    }
    return {std::move(reply_pkt_unique_ptr), rtt, std::nullopt};
}

DnsExchangeResult dns_exchange_from_ldns_pkt(Millis timeout, const SocketAddress &socket_address,
        const ldns_pkt &request_pkt, const SocketFactory *socket_factory,
        SocketFactory::SocketParameters socket_parameters) {
    static constexpr utils::MakeError<DnsExchangeResult> make_error;
    auto [buffer, err] = create_ldns_buffer(request_pkt);
    if (err) {
        return make_error(std::move(err));
    }
    return dns_exchange_from_ldns_buffer(
            timeout, socket_address, *buffer, socket_factory, std::move(socket_parameters));
}

} // namespace ag::dnscrypt
