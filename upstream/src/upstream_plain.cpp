#include <ag_utils.h>
#include <ag_net_utils.h>
#include "upstream_plain.h"
#include <ldns/ag_ext.h>

using std::chrono::milliseconds;
using std::chrono::duration_cast;

static ag::socket_address prepare_address(const std::string &address_string) {
    auto address = ag::utils::str_to_socket_address(address_string);
    if (address.port() == 0) {
        return ag::socket_address(address.addr(), ag::plain_dns::DEFAULT_PORT);
    }
    return address;
}

ag::plain_dns::plain_dns(const upstream_options &opts, const upstream_factory_config &config)
        : upstream(opts, config)
        , m_prefer_tcp(utils::starts_with(opts.address, TCP_SCHEME))
        , m_pool(event_loop::create(),
                 prepare_address(m_prefer_tcp
                                 ? opts.address.substr(TCP_SCHEME.length())
                                 : opts.address)) {}

ag::err_string ag::plain_dns::init() {
    if (!m_pool.address().valid()) {
        return AG_FMT("Passed server address is not valid: {}", this->m_options.address);
    }

    return std::nullopt;
}

ag::plain_dns::exchange_result ag::plain_dns::exchange(ldns_pkt *request_pkt) {
    ldns_status status;
    ldns_buffer_ptr buffer{ldns_buffer_new(REQUEST_BUFFER_INITIAL_CAPACITY)};
    status = ldns_pkt2buffer_wire(&*buffer, request_pkt);
    if (status != LDNS_STATUS_OK) {
        return {nullptr, ldns_get_errorstr_by_id(status)};
    }

    if (!m_prefer_tcp) {
        // UDP request
        uint8_t *reply_data;
        size_t reply_size;
        timeval tv = utils::duration_to_timeval(this->m_options.timeout);
        status = ldns_udp_send(&reply_data, &*buffer, (const sockaddr_storage *) m_pool.address().c_sockaddr(),
                               m_pool.address().c_socklen(), tv, &reply_size);
        if (status != LDNS_STATUS_OK) {
            return {nullptr, utils::ldns_status_to_str(status)};
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
    ag::uint8_view buf{ ldns_buffer_begin(buffer.get()), ldns_buffer_position(buffer.get()) };
    connection::read_result result = m_pool.perform_request(buf, this->m_options.timeout);
    if (result.error.has_value()) {
        return { nullptr, std::move(result.error) };
    }

    const std::vector<uint8_t> &reply = result.reply;
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
    connection_ptr connection = create_connection(bev, m_address);
    add_pending_connection(connection);
    bufferevent_socket_connect(bev, m_address.c_sockaddr(), m_address.c_socklen());
    return { std::move(connection), std::chrono::seconds(0), std::nullopt };
}

const ag::socket_address &ag::tcp_pool::address() const {
    return m_address;
}
