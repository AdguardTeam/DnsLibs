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


/**
 * Pool of TLS connections
 */
class ag::dns_over_tls::tls_pool : public ag::dns_framed_pool {
public:
    /**
     * Create TLS pool
     * @param loop Event loop
     * @param upstream Parent upstream
     * @param bootstrapper Bootstrapper (used to resolve original address)
     */
    tls_pool(event_loop_ptr loop, dns_over_tls *upstream, bootstrapper_ptr &&bootstrapper)
            : dns_framed_pool(std::move(loop)), m_upstream(upstream), m_bootstrapper(std::move(bootstrapper)) {
    }

private:
    get_result get() override;

    /** Parent upstream */
    dns_over_tls *m_upstream = nullptr;
    /** Bootstrapper for server address */
    bootstrapper_ptr m_bootstrapper;

    connection::read_result perform_request_inner(uint8_view buf, std::chrono::milliseconds timeout) override;

    get_result create();
};


ag::connection_pool::get_result ag::dns_over_tls::tls_pool::get() {
    std::scoped_lock l(m_mutex);
    if (!m_connections.empty()) {
        return {*m_connections.rbegin(), std::chrono::seconds(0), std::nullopt};
    }
    return create();
}

ag::connection_pool::get_result ag::dns_over_tls::tls_pool::create() {
    static constexpr utils::make_error<ag::connection_pool::get_result> make_error;

    bootstrapper::resolve_result resolve_result = m_bootstrapper->get();
    if (resolve_result.error.has_value()) {
        return make_error(std::move(resolve_result.error), nullptr, resolve_result.time_elapsed);
    }
    assert(!resolve_result.addresses.empty());

    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
    SSL_CTX_set_cert_verify_callback(ctx, dns_over_tls::ssl_verify_callback, nullptr);
    SSL *ssl = SSL_new(ctx);
    int options = BEV_OPT_THREADSAFE | BEV_OPT_DEFER_CALLBACKS | BEV_OPT_UNLOCK_CALLBACKS | BEV_OPT_CLOSE_ON_FREE;
    bufferevent *bev = bufferevent_openssl_socket_new(m_loop->c_base(), -1, ssl,
                                                      BUFFEREVENT_SSL_CONNECTING,
                                                      options);
    SSL_set_tlsext_host_name(ssl, m_upstream->m_server_name.c_str());
    SSL_set_app_data(ssl, m_upstream);

    const socket_address &address = resolve_result.addresses[0];
    connection_ptr connection = create_connection(bev, address);
    add_pending_connection(connection);
    bufferevent_socket_connect(bev, address.c_sockaddr(), address.c_socklen());
    SSL_CTX_free(ctx);
    return { std::move(connection), resolve_result.time_elapsed, std::nullopt };
}

ag::connection::read_result ag::dns_over_tls::tls_pool::perform_request_inner(uint8_view buf, std::chrono::milliseconds timeout) {
    auto[conn, elapsed, err] = get();
    if (!conn) {
        return { {}, std::move(err) };
    }

    timeout -= duration_cast<milliseconds>(elapsed);
    if (timeout < milliseconds(0)) {
        return { {}, AG_FMT("DNS server name resolving took too much time: {}", elapsed) };
    }

    connection::write_result write_result = conn->write(buf);
    if (write_result.error.has_value()) {
        m_bootstrapper->remove_resolved(conn->address);
        return { {}, std::move(write_result.error) };
    }

    connection::read_result read_result = conn->read(write_result.id, timeout);
    if (read_result.error.has_value()) {
        m_bootstrapper->remove_resolved(conn->address);
    }

    return read_result;
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

static ag::bootstrapper_ptr create_bootstrapper(const ag::logger &log, const ag::upstream_options &opts,
        const ag::upstream_factory_config &config) {
    std::string_view address;

    std::optional<std::string> resolved = get_resolved_ip(log, opts.resolved_server_ip);
    if (resolved.has_value()) {
        address = resolved.value();
    } else {
        address = get_host_name(opts.address);
    }

    return std::make_unique<ag::bootstrapper>(
        ag::bootstrapper::params{ address, ag::dns_over_tls::DEFAULT_PORT,
                                  opts.bootstrap, opts.timeout, config });
}

ag::dns_over_tls::dns_over_tls(const upstream_options &opts, const upstream_factory_config &config)
        : upstream(opts, config)
        , m_server_name(get_host_name(opts.address))
{}

ag::err_string ag::dns_over_tls::init() {
    if (this->m_options.bootstrap.empty()
            && std::holds_alternative<std::monostate>(this->m_options.resolved_server_ip)
            && !socket_address(get_host_name(this->m_options.address), 0).valid()) {
        std::string err = "At least one the following should be true: server address is specified, url contains valid server address as a host name, bootstrap server is specified";
        errlog(m_log, "{}", err);
        return err;
    }

    bootstrapper_ptr bootstrapper = create_bootstrapper(m_log, this->m_options, this->m_config);
    if (err_string err = bootstrapper->init(); err.has_value()) {
        std::string err_message = AG_FMT("Failed to create bootstrapper: {}", err.value());
        errlog(m_log, "{}", err_message);
        return err_message;
    }

    m_pool = std::make_unique<tls_pool>(event_loop::create(), this, std::move(bootstrapper));

    return std::nullopt;
}

ag::dns_over_tls::~dns_over_tls() = default;

int ag::dns_over_tls::ssl_verify_callback(X509_STORE_CTX *ctx, void *arg) {
    SSL *ssl = (SSL *)X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
    ag::dns_over_tls *upstream = (ag::dns_over_tls *)SSL_get_app_data(ssl);

    if (upstream->m_config.cert_verifier == nullptr) {
        dbglog(upstream->m_log, "Cannot verify certificate due to verifier is not set");
        return 0;
    }

    if (err_string err = upstream->m_config.cert_verifier->verify(ctx, SSL_get_servername(ssl, SSL_get_servername_type(ssl)));
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

    ag::uint8_view buf{ ldns_buffer_begin(buffer.get()), ldns_buffer_position(buffer.get()) };
    connection::read_result result = m_pool->perform_request(buf, this->m_options.timeout);
    if (result.error.has_value()) {
        return { nullptr, std::move(result.error) };
    }

    const std::vector<uint8_t> &reply = result.reply;
    status = ldns_wire2pkt(&reply_pkt, reply.data(), reply.size());
    if (status != LDNS_STATUS_OK) {
        return {nullptr, ldns_get_errorstr_by_id(status)};
    }
    return {ldns_pkt_ptr(reply_pkt), std::nullopt};
}
