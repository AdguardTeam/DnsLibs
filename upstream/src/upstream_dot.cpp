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

    bootstrapper::resolve_result resolve_result = m_bootstrapper->get();
    if (resolve_result.error.has_value()) {
        return make_error(std::move(resolve_result.error), nullptr, resolve_result.time_elapsed);
    }
    assert(!resolve_result.addresses.empty());

    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    SSL *ssl = SSL_new(ctx);
    int options = BEV_OPT_THREADSAFE | BEV_OPT_DEFER_CALLBACKS | BEV_OPT_UNLOCK_CALLBACKS | BEV_OPT_CLOSE_ON_FREE;
    bufferevent *bev = bufferevent_openssl_socket_new(m_loop->c_base(), -1, ssl,
                                                      BUFFEREVENT_SSL_CONNECTING,
                                                      options);
    SSL_set_tlsext_host_name(ssl, m_upstream->m_server_name.c_str());
    SSL_set_verify(ssl, SSL_VERIFY_PEER, dns_over_tls::ssl_verify_callback);
    SSL_set_app_data(ssl, m_upstream);

    const socket_address &address = resolve_result.addresses[0];
    dns_framed_connection_ptr connection = ag::dns_framed_connection::create(this, bev, address);
    bufferevent_socket_connect(bev, address.c_sockaddr(), address.c_socklen());
    add_pending_connection(connection);
    SSL_CTX_free(ctx);
    return { std::move(connection), resolve_result.time_elapsed, std::nullopt };
}

const ag::bootstrapper *ag::tls_pool::bootstrapper() {
    return m_bootstrapper.get();
}

static std::optional<std::string> get_resolved_ip(const ag::logger &log, const ag::ip_address_variant &addr) {
    if (std::holds_alternative<std::monostate>(addr)) {
        return std::nullopt;
    }

    ag::socket_address parsed;
    if (const ag::ipv4_address_array *ipv4 = std::get_if<ag::ipv4_address_array>(&addr);
            ipv4 != nullptr) {
        parsed = ag::socket_address({ ipv4->data(), ipv4->size() }, ag::dns_over_tls::DEFAULT_PORT);
    } else if (const ag::ipv6_address_array *ipv6 = std::get_if<ag::ipv6_address_array>(&addr);
            ipv6 != nullptr) {
        parsed = ag::socket_address({ ipv6->data(), ipv6->size() }, ag::dns_over_tls::DEFAULT_PORT);
    } else {
        assert(0);
        errlog(log, "Wrong resolved server ip address");
        return std::nullopt;
    }

    if (parsed.valid()) {
        return parsed.str();
    } else {
        warnlog(log, "Failed to parse resolved server ip address, upstream may not be able to resolve DNS server address");
        return std::nullopt;
    }
}

static std::string_view get_host_name(std::string_view url) {
    assert(ag::utils::starts_with(url, ag::dns_over_tls::SCHEME));
    url.remove_prefix(ag::dns_over_tls::SCHEME.length());
    if (url.back() == '/') {
        url.remove_suffix(1);
    }
    return ag::utils::split_host_port(url).first;
}

static ag::bootstrapper_ptr create_bootstrapper(const ag::logger &log, const ag::upstream::options &opts,
        const ag::upstream_factory::config &config) {
    std::string_view address;

    std::optional<std::string> resolved = get_resolved_ip(log, opts.resolved_server_ip);
    if (resolved.has_value()) {
        address = resolved.value();
    } else {
        address = get_host_name(opts.address);
    }

    return std::make_unique<ag::bootstrapper>(
        ag::bootstrapper::params{ address, ag::dns_over_tls::DEFAULT_PORT, true,
            opts.bootstrap, opts.timeout, config });
}

ag::dns_over_tls::dns_over_tls(const ag::upstream::options &opts, const ag::upstream_factory::config &config)
        : upstream(opts)
        , m_pool(event_loop::create(), this, create_bootstrapper(m_log, opts, config))
        , m_verifier(config.cert_verifier)
        , m_server_name(get_host_name(opts.address))
{}

int ag::dns_over_tls::ssl_verify_callback(int ok, X509_STORE_CTX *ctx) {
    SSL *ssl = (SSL *)X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
    ag::dns_over_tls *upstream = (ag::dns_over_tls *)SSL_get_app_data(ssl);

    if (upstream->m_verifier == nullptr) {
        dbglog(upstream->m_log, "Cannot verify certificate due to verifier is not set");
        return 0;
    }

    if (err_string err = upstream->m_verifier->verify(ctx, SSL_get_servername(ssl, SSL_get_servername_type(ssl)));
            err.has_value()) {
        dbglog(upstream->m_log, "Failed to verify certificate: {}", err.value());
        return 0;
    }

    tracelog(upstream->m_log, "Verified successfully");

    return 1;
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
    tracelog(m_log, "Resolve took {}", elapsed);
    if (!conn) {
        tracelog(m_log, "Resolve failed: {}", err.value());
        return {nullptr, err};
    }
    ag::uint8_view buf{ldns_buffer_begin(&*buffer), ldns_buffer_position(&*buffer)};
    int id = conn->write(buf);

    if (this->opts.timeout <= elapsed) {
        return { nullptr, AG_FMT("DNS server name resolving took too much time: {}", elapsed) };
    }

    auto timeout = this->opts.timeout - duration_cast<milliseconds>(elapsed);
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
