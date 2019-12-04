#include <event2/event.h>
#include <event2/bufferevent.h>
#include <event2/thread.h>
#include <event2/bufferevent_ssl.h>
#include <openssl/x509v3.h>
#include <openssl/ssl.h>
#include "upstream_dot.h"
#include <ag_defs.h>
#include <ag_utils.h>

using std::chrono::milliseconds;
using std::chrono::duration_cast;

ag::connection_pool::get_result ag::tls_pool::get() {
    std::scoped_lock l(m_mutex);
    if (!m_connections.empty()) {
        return {*m_connections.rbegin(), std::chrono::seconds(0), std::nullopt};
    }
    return create();
}

ag::connection_pool::get_result ag::tls_pool::create() {
    static constexpr utils::make_error<ag::connection_pool::get_result> make_error;
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    SSL *ssl = SSL_new(ctx);
    int options = BEV_OPT_THREADSAFE | BEV_OPT_DEFER_CALLBACKS | BEV_OPT_UNLOCK_CALLBACKS | BEV_OPT_CLOSE_ON_FREE;
    bufferevent *bev = bufferevent_openssl_socket_new(m_loop->c_base(), -1, ssl,
                                                      BUFFEREVENT_SSL_CONNECTING,
                                                      options);
    auto[address, server_name, time_elapsed, error] = m_bootstrapper->get();
    if (error) {
        return make_error(std::move(error), nullptr, time_elapsed);
    }
    SSL_set_tlsext_host_name(ssl, server_name.c_str());
    dns_framed_connection_ptr connection = ag::dns_framed_connection::create(this, bev, *address);
    bufferevent_socket_connect(bev, address->c_sockaddr(), address->c_socklen());
    add_pending_connection(connection);
    SSL_CTX_free(ctx);
    return {connection, time_elapsed, std::nullopt};
}

ag::bootstrapper_ptr ag::tls_pool::bootstrapper() {
    return m_bootstrapper;
}

ag::dns_over_tls::dns_over_tls(bootstrapper_ptr bootstrapper, milliseconds timeout)
        : m_pool(event_loop::create(), std::move(bootstrapper)),
          m_timeout(timeout) {
}

ag::dns_over_tls::exchange_result ag::dns_over_tls::exchange(ldns_pkt *request_pkt) {
    ldns_pkt *reply_pkt = nullptr;
    ldns_status status;

    using ldns_buffer_ptr = std::unique_ptr<ldns_buffer, ag::ftor<&ldns_buffer_free>>;
    ldns_buffer_ptr buffer{ldns_buffer_new(REQUEST_BUFFER_INITIAL_CAPACITY)};
    status = ldns_pkt2buffer_wire(&*buffer, request_pkt);
    if (status != LDNS_STATUS_OK) {
        return {nullptr, ldns_get_errorstr_by_id(status)};
    }

    auto[conn, elapsed, err] = m_pool.get();
    if (!conn) {
        return {nullptr, err};
    }
    ag::uint8_view buf{ldns_buffer_begin(&*buffer), ldns_buffer_position(&*buffer)};
    int id = conn->write(buf);

    auto timeout = m_timeout - duration_cast<milliseconds>(elapsed);
    auto[reply, read_error] = conn->read(id, timeout);
    if (read_error) {
        return {nullptr, read_error};
    }
    status = ldns_wire2pkt(&reply_pkt, reply.data(), reply.size());
    if (status != LDNS_STATUS_OK) {
        return {nullptr, ldns_get_errorstr_by_id(status)};
    }
    return {ldns_pkt_ptr(reply_pkt), std::nullopt};
}

std::string ag::dns_over_tls::address() {
    return m_pool.bootstrapper()->address();
}
