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
        : dns_framed_pool(std::move(loop), upstream)
        , m_upstream(upstream)
        , m_bootstrapper(std::move(bootstrapper))
    {}

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

    // https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xml#alpn-protocol-ids
    static const std::string DOT_ALPN = "dot";

    const socket_address &address = resolve_result.addresses[0];
    connection_ptr connection = create_connection(address,
            socket_factory::secure_socket_parameters{
                    &m_upstream->m_tls_session_cache,
                    m_upstream->m_server_name,
                    { DOT_ALPN },
            });
    add_pending_connection(connection);
    return { std::move(connection), resolve_result.time_elapsed, std::nullopt };
}

ag::connection::read_result ag::dns_over_tls::tls_pool::perform_request_inner(uint8_view buf, std::chrono::milliseconds timeout) {
    auto[conn, elapsed, err] = get();
    if (!conn) {
        return { {}, std::move(err) };
    }

    if (buf.size() < 2) {
        return { {}, "Too short request" };
    }

    timeout -= duration_cast<milliseconds>(elapsed);
    if (timeout < milliseconds(0)) {
        return { {}, AG_FMT("DNS server name resolving took too much time: {}", elapsed) };
    }

    uint16_t id = ntohs(*(uint16_t *)buf.data());
    if (err_string e = conn->wait_connect_result(id, timeout); e.has_value()) {
        return { {}, std::move(e) };
    }

    if (err_string e = conn->write(id, buf); e.has_value()) {
        return { {}, std::move(e) };
    }

    connection::read_result read_result = conn->read(id, timeout);
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
        errlog(log, "Wrong resolved server ip address");
        assert(0);
        return std::nullopt;
    }

    if (parsed.valid()) {
        return parsed.str();
    } else {
        warnlog(log, "Failed to parse resolved server ip address, upstream may not be able to resolve DNS server address");
        return std::nullopt;
    }
}

static std::string_view strip_dot_url(std::string_view url) {
    assert(ag::utils::starts_with(url, ag::dns_over_tls::SCHEME));
    url.remove_prefix(ag::dns_over_tls::SCHEME.length());
    url = url.substr(0, url.find('/'));
    return url;
}

static std::string_view get_host_name(std::string_view url) {
    return ag::utils::trim(ag::utils::split_host_port(strip_dot_url(url)).first);
}

static ag::bootstrapper_ptr create_bootstrapper(const ag::logger &log, const ag::upstream_options &opts,
        const ag::upstream_factory_config &config) {
    std::string_view address;
    int port = 0;

    std::optional<std::string> resolved = get_resolved_ip(log, opts.resolved_server_ip);
    if (resolved.has_value()) {
        address = resolved.value();
    } else {
        auto[host, port_str] = ag::utils::split_host_port(strip_dot_url(opts.address));
        address = host;
        if (!port_str.empty()) {
            port = std::strtol(std::string(port_str).c_str(), nullptr, 10);
        }
    }

    return std::make_unique<ag::bootstrapper>(
        ag::bootstrapper::params{ address, (port == 0) ? ag::dns_over_tls::DEFAULT_PORT : port,
                                  opts.bootstrap, opts.timeout, config,
                                  opts.outbound_interface });
}

ag::dns_over_tls::dns_over_tls(const upstream_options &opts, const upstream_factory_config &config)
        : upstream(opts, config)
        , m_server_name(get_host_name(opts.address))
        , m_tls_session_cache(opts.address)
{}

ag::err_string ag::dns_over_tls::init() {
    if (auto hostname = get_host_name(this->m_options.address);
            hostname.empty() || (this->m_options.bootstrap.empty()
            && std::holds_alternative<std::monostate>(this->m_options.resolved_server_ip)
            && !socket_address(hostname, 0).valid())) {
        std::string err = "At least one the following should be true: server address is specified, "
                          "url contains valid server address as a host name, bootstrap server is specified";
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

ag::dns_over_tls::exchange_result ag::dns_over_tls::exchange(ldns_pkt *request_pkt, const dns_message_info *) {
    ldns_buffer_ptr buffer{ldns_buffer_new(REQUEST_BUFFER_INITIAL_CAPACITY)};
    ldns_status status = ldns_pkt2buffer_wire(&*buffer, request_pkt);
    if (status != LDNS_STATUS_OK) {
        return {nullptr, ldns_get_errorstr_by_id(status)};
    }

    ag::uint8_view buf{ ldns_buffer_begin(buffer.get()), ldns_buffer_position(buffer.get()) };
    connection::read_result result = m_pool->perform_request(buf, this->m_options.timeout);
    if (result.error.has_value()) {
        return { nullptr, std::move(result.error) };
    }

    ldns_pkt *reply_pkt = nullptr;
    const std::vector<uint8_t> &reply = result.reply;
    status = ldns_wire2pkt(&reply_pkt, reply.data(), reply.size());
    if (status != LDNS_STATUS_OK) {
        return {nullptr, ldns_get_errorstr_by_id(status)};
    }
    return {ldns_pkt_ptr(reply_pkt), std::nullopt};
}
