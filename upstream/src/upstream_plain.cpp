#include "upstream_plain.h"

std::string ag::plain_dns::address() {
    return m_socket_address.str();
}

ag::plain_dns::plain_dns(std::string_view address, const std::chrono::milliseconds &timeout,
                         bool prefer_tcp) :
        m_pool(event_loop::create()),
        m_timeout(timeout),
        m_prefer_tcp(prefer_tcp),
        m_socket_address(address) {

    if (m_socket_address.port() == 0) {
        auto addr = m_socket_address.addr();
        m_socket_address = ag::socket_address({addr.data(), addr.size()}, 53);
    }
}

std::pair<ldns_pkt *, ag::err_string> ag::plain_dns::exchange(ldns_pkt *request_pkt) {
    ldns_pkt *reply_pkt = nullptr;
    ldns_status status;

    using ldns_buffer_ptr = std::unique_ptr<ldns_buffer, decltype(&ldns_buffer_free)>;
    ldns_buffer_ptr buffer = {ldns_buffer_new(LDNS_MAX_PACKETLEN), &ldns_buffer_free};
    status = ldns_pkt2buffer_wire(&*buffer, request_pkt);
    if (status != LDNS_STATUS_OK) {
        return {nullptr, ldns_get_errorstr_by_id(status)};
    }

    if (!m_prefer_tcp) {
        // UDP request
        uint8_t *reply_data;
        size_t reply_size;
        timeval tv = ag::util::duration_to_timeval(m_timeout);
        status = ldns_udp_send(&reply_data, &*buffer, (const sockaddr_storage *) m_socket_address.c_sockaddr(),
                               m_socket_address.c_socklen(), tv, &reply_size);
        if (status != LDNS_STATUS_OK) {
            return {nullptr, ldns_get_errorstr_by_id(status)};
        }
        status = ldns_wire2pkt(&reply_pkt, reply_data, reply_size);
        std::free(reply_data);
        if (status != LDNS_STATUS_OK) {
            return {nullptr, ldns_get_errorstr_by_id(status)};
        }
        // If not truncated, return result. Otherwise, try TCP.
        if (!ldns_pkt_tc(reply_pkt)) {
            return {reply_pkt, std::nullopt};
        }
    }

    // TCP request
    size_t len = ldns_buffer_position(&*buffer);
    using uint8_t_ptr = std::unique_ptr<uint8_t, decltype(&std::free)>;
    uint8_t_ptr buf = {(uint8_t *) ldns_buffer_export(&*buffer), &std::free};
    {
        ag::connection_ptr conn = m_pool.get_connection_to(m_socket_address);
        int id = conn->write({&*buf, len});

        auto[reply, read_error] = conn->read(id, m_timeout);
        if (read_error) {
            return {reply_pkt, read_error};
        }
        status = ldns_wire2pkt(&reply_pkt, reply.data(), reply.size());
        if (status != LDNS_STATUS_OK) {
            return {nullptr, ldns_get_errorstr_by_id(status)};
        }
        return {reply_pkt, std::nullopt};
    }
}
