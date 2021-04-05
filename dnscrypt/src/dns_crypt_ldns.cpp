#include <ldns/error.h>
#include <ldns/net.h>
#include <ldns/ag_ext.h>
#include "dns_crypt_ldns.h"
#include <ag_utils.h>
#include <ag_net_utils.h>
#include <ag_net_consts.h>

ag::ldns_pkt_ptr ag::dnscrypt::create_request_ldns_pkt(ldns_rr_type rr_type, ldns_rr_class rr_class, uint16_t flags,
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

ag::dnscrypt::create_ldns_buffer_result ag::dnscrypt::create_ldns_buffer(const ldns_pkt &request_pkt) {
    static constexpr utils::make_error<create_ldns_buffer_result> make_error;
    ldns_buffer_ptr result(ldns_buffer_new(REQUEST_BUFFER_INITIAL_CAPACITY));
    ldns_status status = ldns_pkt2buffer_wire(result.get(), &request_pkt);
    if (status != LDNS_STATUS_OK) {
        return make_error(ldns_get_errorstr_by_id(status));
    }
    return {std::move(result), std::nullopt};
}

ag::dnscrypt::create_ldns_pkt_result ag::dnscrypt::create_ldns_pkt(uint8_t *data, size_t size) {
    static constexpr utils::make_error<create_ldns_pkt_result> make_error;
    ldns_pkt *pkt = nullptr;
    ldns_status status = ldns_wire2pkt(&pkt, data, size);
    ldns_pkt_ptr result(pkt);
    if (status != LDNS_STATUS_OK) {
        return make_error(ldns_get_errorstr_by_id(status));
    }
    return {std::move(result), std::nullopt};
}

ag::dnscrypt::dns_exchange_allocated_result ag::dnscrypt::dns_exchange_allocated(std::chrono::milliseconds timeout,
                                                                                 const socket_address &socket_address,
                                                                                 ldns_buffer &buffer,
                                                                                 protocol local_protocol,
                                                                                 preparefd_cb prepare_fd) {
    static constexpr utils::make_error<dns_exchange_allocated_result> make_error;
    uint8_t *reply_data = nullptr;
    size_t reply_size = 0;
    auto tv = utils::duration_to_timeval(timeout);
    auto send_func = local_protocol == protocol::TCP ? ldns_tcp_send : ldns_udp_send;
    utils::timer timer;
    ldns_status status = send_func(&reply_data, &buffer,
                                   reinterpret_cast<const sockaddr_storage *>(socket_address.c_sockaddr()),
                                   socket_address.c_socklen(), tv, &reply_size,
                                   [](int fd, const sockaddr *peer, void *arg) -> int {
                                       auto &f = *((preparefd_cb *) arg);
                                       ag::socket_address addr{peer};
                                       return !f || f(fd, addr);
                                   }, &prepare_fd);
    if (status != LDNS_STATUS_OK) {
        return make_error(utils::ldns_status_to_str(status));
    }
    auto reply_data_unique_ptr = utils::make_allocated_unique(reply_data);
    auto rtt = timer.elapsed<std::chrono::milliseconds>();
    return {std::move(reply_data_unique_ptr), reply_size, rtt, std::nullopt};
}

ag::dnscrypt::dns_exchange_result ag::dnscrypt::dns_exchange_from_ldns_buffer(std::chrono::milliseconds timeout,
                                                                              const socket_address &socket_address,
                                                                              ldns_buffer &buffer, protocol protocol,
                                                                              preparefd_cb prepare_fd) {
    static constexpr utils::make_error<dns_exchange_result> make_error;
    auto[reply, reply_size, rtt, allocated_err] = dns_exchange_allocated(timeout, socket_address, buffer, protocol,
                                                                         std::move(prepare_fd));
    if (allocated_err) {
        return make_error(std::move(allocated_err));
    }
    auto[reply_pkt_unique_ptr, reply_err] = create_ldns_pkt(reply.get(), reply_size);
    if (reply_err) {
        return make_error(std::move(reply_err));
    }
    if (ldns_pkt_tc(reply_pkt_unique_ptr.get())) {
        return make_error("Truncated response");
    }
    return {std::move(reply_pkt_unique_ptr), rtt, std::nullopt};
}

ag::dnscrypt::dns_exchange_result ag::dnscrypt::dns_exchange_from_ldns_pkt(std::chrono::milliseconds timeout,
                                                                           const socket_address &socket_address,
                                                                           const ldns_pkt &request_pkt,
                                                                           protocol protocol,
                                                                           preparefd_cb prepare_fd) {
    static constexpr utils::make_error<dns_exchange_result> make_error;
    auto[buffer, err] = create_ldns_buffer(request_pkt);
    if (err) {
        return make_error(std::move(err));
    }
    return dns_exchange_from_ldns_buffer(timeout, socket_address, *buffer, protocol, std::move(prepare_fd));
}
