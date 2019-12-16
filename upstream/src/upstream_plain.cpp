#include <ag_utils.h>
#include "upstream_plain.h"

using std::chrono::milliseconds;
using std::chrono::duration_cast;

ag::plain_dns::plain_dns(const ag::upstream::options &opts)
        : upstream(opts)
        , m_prefer_tcp(ag::utils::starts_with(opts.address, TCP_SCHEME))
        , m_socket_address(m_prefer_tcp ? &opts.address[TCP_SCHEME.length()] : opts.address)
        , m_pool(event_loop::create(), m_socket_address)
{
    if (m_socket_address.port() == 0) {
        auto addr = m_socket_address.addr();
        m_socket_address = ag::socket_address({addr.data(), addr.size()}, DEFAULT_PORT);
    }
}

ag::plain_dns::exchange_result ag::plain_dns::exchange(ldns_pkt *request_pkt) {
    ldns_status status;

    using ldns_buffer_ptr = std::unique_ptr<ldns_buffer, ag::ftor<&ldns_buffer_free>>;
    ldns_buffer_ptr buffer{ldns_buffer_new(REQUEST_BUFFER_INITIAL_CAPACITY)};
    status = ldns_pkt2buffer_wire(&*buffer, request_pkt);
    if (status != LDNS_STATUS_OK) {
        return {nullptr, ldns_get_errorstr_by_id(status)};
    }

    if (!m_prefer_tcp) {
        // UDP request
        uint8_t *reply_data;
        size_t reply_size;
        timeval tv = utils::duration_to_timeval(this->opts.timeout);
        status = ldns_udp_send(&reply_data, &*buffer, (const sockaddr_storage *) m_socket_address.c_sockaddr(),
                               m_socket_address.c_socklen(), tv, &reply_size);
        if (status != LDNS_STATUS_OK) {
            return {nullptr, ldns_get_errorstr_by_id(status)};
        }

        ldns_pkt *reply_pkt = nullptr;
        status = ldns_wire2pkt(&reply_pkt, reply_data, reply_size);
        std::free(reply_data);
        if (status != LDNS_STATUS_OK) {
            return {nullptr, ldns_get_errorstr_by_id(status)};
        }
        // If not truncated, return result. Otherwise, try TCP.
        if (!ldns_pkt_tc(reply_pkt)) {
            return {ldns_pkt_ptr(reply_pkt), std::nullopt};
        }
        ldns_pkt_free(reply_pkt);
    }

    // TCP request
    auto[conn, elapsed, err] = m_pool.get();
    if (!conn) {
        return {nullptr, err};
    }
    ag::uint8_view buf{ldns_buffer_begin(&*buffer), ldns_buffer_position(&*buffer)};
    int id = conn->write(buf);

    auto timeout = this->opts.timeout - duration_cast<milliseconds>(elapsed);
    auto[reply, read_error] = conn->read(id, timeout);
    if (read_error) {
        return {nullptr, read_error};
    }
    ldns_pkt *reply_pkt = nullptr;
    status = ldns_wire2pkt(&reply_pkt, reply.data(), reply.size());
    if (status != LDNS_STATUS_OK) {
        return {nullptr, ldns_get_errorstr_by_id(status)};
    }
    return {ldns_pkt_ptr(reply_pkt), std::nullopt};
}

ag::connection_pool::get_result ag::tcp_pool::get() {
    std::scoped_lock l(m_mutex);
    if (!m_connections.empty()) {
        return {*m_connections.begin(), std::chrono::seconds(0), std::nullopt};
    }
    return create();
}

ag::connection_pool::get_result ag::tcp_pool::create() {
    int options = BEV_OPT_THREADSAFE | BEV_OPT_DEFER_CALLBACKS | BEV_OPT_UNLOCK_CALLBACKS | BEV_OPT_CLOSE_ON_FREE;
    bufferevent *bev = bufferevent_socket_new(m_loop->c_base(), -1, options);
    dns_framed_connection_ptr connection = ag::dns_framed_connection::create(this, bev, m_address);
    bufferevent_socket_connect(bev, m_address.c_sockaddr(), m_address.c_socklen());
    add_pending_connection(connection);
    return {connection, std::chrono::seconds(0), std::nullopt};
}
