#include "upstream_dot.h"
#include "common/defs.h"
#include "common/utils.h"
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

using std::chrono::duration_cast;

namespace ag {

static constexpr auto DOT_IDLE_TIMEOUT = Secs(30);

/**
 * Pool of TLS connections
 */
class DotUpstream::TlsPool : public DnsFramedPool {
public:
    /**
     * Create TLS pool
     * @param loop Event loop
     * @param upstream Parent upstream
     * @param bootstrapper Bootstrapper (used to resolve original address)
     */
    TlsPool(EventLoopPtr loop, DotUpstream *upstream, BootstrapperPtr &&bootstrapper)
            : DnsFramedPool(std::move(loop), upstream)
            , m_upstream(upstream)
            , m_bootstrapper(std::move(bootstrapper)) {
    }

private:
    GetResult get() override;

    /** Parent upstream */
    DotUpstream *m_upstream = nullptr;
    /** Bootstrapper for server address */
    BootstrapperPtr m_bootstrapper;

    Connection::ReadResult perform_request_inner(Uint8View buf, Millis timeout) override;

    GetResult create();
};

ConnectionPool::GetResult DotUpstream::TlsPool::get() {
    std::scoped_lock l(m_mutex);
    if (!m_connections.empty()) {
        return {*m_connections.rbegin(), Secs(0), std::nullopt};
    }
    return create();
}

ConnectionPool::GetResult DotUpstream::TlsPool::create() {
    static constexpr utils::MakeError<ConnectionPool::GetResult> make_error;

    Bootstrapper::ResolveResult resolve_result = m_bootstrapper->get();
    if (resolve_result.error.has_value()) {
        return make_error(std::move(resolve_result.error), nullptr, resolve_result.time_elapsed);
    }
    assert(!resolve_result.addresses.empty());

    // https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xml#alpn-protocol-ids
    static const std::string DOT_ALPN = "dot";

    const SocketAddress &address = resolve_result.addresses[0];
    ConnectionPtr connection = create_connection(address,
            SocketFactory::SecureSocketParameters{
                    &m_upstream->m_tls_session_cache,
                    m_upstream->m_server_name,
                    {DOT_ALPN},
            },
            DOT_IDLE_TIMEOUT);
    add_pending_connection(connection);
    return {std::move(connection), resolve_result.time_elapsed, std::nullopt};
}

Connection::ReadResult DotUpstream::TlsPool::perform_request_inner(Uint8View buf, Millis timeout) {
    auto [conn, elapsed, err] = get();
    if (!conn) {
        return {{}, std::move(err)};
    }

    if (buf.size() < 2) {
        return {{}, "Too short request"};
    }

    timeout -= duration_cast<Millis>(elapsed);
    if (timeout < Millis(0)) {
        return {{}, AG_FMT("DNS server name resolving took too much time: {}", elapsed)};
    }

    uint16_t id = ntohs(*(uint16_t *) buf.data());
    if (ErrString e = conn->wait_connect_result(id, timeout); e.has_value()) {
        remove_from_all(conn);
        m_bootstrapper->remove_resolved(conn->address);
        return {{}, std::move(e)};
    }

    if (ErrString e = conn->write(id, buf); e.has_value()) {
        remove_from_all(conn);
        m_bootstrapper->remove_resolved(conn->address);
        return {{}, std::move(e)};
    }

    Connection::ReadResult read_result = conn->read(id, timeout);
    if (read_result.error.has_value()) {
        remove_from_all(conn);
        m_bootstrapper->remove_resolved(conn->address);
    }

    return read_result;
}

static std::optional<std::string> get_resolved_ip(const Logger &log, const IpAddress &addr) {
    if (std::holds_alternative<std::monostate>(addr)) {
        return std::nullopt;
    }

    SocketAddress parsed;
    if (const Ipv4Address *ipv4 = std::get_if<Ipv4Address>(&addr); ipv4 != nullptr) {
        parsed = SocketAddress({ipv4->data(), ipv4->size()}, ag::DEFAULT_DOT_PORT);
    } else if (const Ipv6Address *ipv6 = std::get_if<Ipv6Address>(&addr); ipv6 != nullptr) {
        parsed = SocketAddress({ipv6->data(), ipv6->size()}, ag::DEFAULT_DOT_PORT);
    } else {
        errlog(log, "Wrong resolved server ip address");
        assert(0);
        return std::nullopt;
    }

    if (parsed.valid()) {
        return parsed.str();
    } else {
        warnlog(log,
                "Failed to parse resolved server ip address, upstream may not be able to resolve DNS server address");
        return std::nullopt;
    }
}

static std::string_view strip_dot_url(std::string_view url) {
    assert(ag::utils::starts_with(url, DotUpstream::SCHEME));
    url.remove_prefix(DotUpstream::SCHEME.length());
    url = url.substr(0, url.find('/'));
    return url;
}

static std::string_view get_host_name(std::string_view url) {
    return ag::utils::trim(ag::utils::split_host_port(strip_dot_url(url)).first);
}

static BootstrapperPtr create_bootstrapper(
        const Logger &log, const UpstreamOptions &opts, const UpstreamFactoryConfig &config) {
    std::string_view address;
    int port = 0;

    std::optional<std::string> resolved = get_resolved_ip(log, opts.resolved_server_ip);
    if (resolved.has_value()) {
        address = resolved.value();
    } else {
        auto [host, port_str] = ag::utils::split_host_port(strip_dot_url(opts.address));
        address = host;
        if (!port_str.empty()) {
            port = std::strtol(std::string(port_str).c_str(), nullptr, 10);
        }
    }

    return std::make_unique<Bootstrapper>(Bootstrapper::Params{address, (port == 0) ? ag::DEFAULT_DOT_PORT : port,
            opts.bootstrap, opts.timeout, config, opts.outbound_interface});
}

DotUpstream::DotUpstream(const UpstreamOptions &opts, const UpstreamFactoryConfig &config)
        : Upstream(opts, config)
        , m_log("DOT upstream")
        , m_server_name(get_host_name(opts.address))
        , m_tls_session_cache(opts.address) {
}

ErrString DotUpstream::init() {
    if (auto hostname = get_host_name(m_options.address); hostname.empty()
            || (m_options.bootstrap.empty() && std::holds_alternative<std::monostate>(m_options.resolved_server_ip)
                    && !SocketAddress(hostname, 0).valid())) {
        std::string err = "At least one the following should be true: server address is specified, "
                          "url contains valid server address as a host name, bootstrap server is specified";
        errlog(m_log, "{}", err);
        return err;
    }

    BootstrapperPtr bootstrapper = create_bootstrapper(m_log, m_options, m_config);
    if (ErrString err = bootstrapper->init(); err.has_value()) {
        std::string err_message = AG_FMT("Failed to create bootstrapper: {}", err.value());
        errlog(m_log, "{}", err_message);
        return err_message;
    }

    m_pool = std::make_unique<TlsPool>(EventLoop::create(), this, std::move(bootstrapper));

    return std::nullopt;
}

DotUpstream::~DotUpstream() = default;

DotUpstream::ExchangeResult DotUpstream::exchange(ldns_pkt *request_pkt, const DnsMessageInfo *) {
    ldns_buffer_ptr buffer{ldns_buffer_new(REQUEST_BUFFER_INITIAL_CAPACITY)};
    ldns_status status = ldns_pkt2buffer_wire(&*buffer, request_pkt);
    if (status != LDNS_STATUS_OK) {
        return {nullptr, ldns_get_errorstr_by_id(status)};
    }

    Uint8View buf{ldns_buffer_begin(buffer.get()), ldns_buffer_position(buffer.get())};
    Connection::ReadResult result = m_pool->perform_request(buf, m_options.timeout);
    if (result.error.has_value()) {
        return {nullptr, std::move(result.error)};
    }

    ldns_pkt *reply_pkt = nullptr;
    const Uint8Vector &reply = result.reply;
    status = ldns_wire2pkt(&reply_pkt, reply.data(), reply.size());
    if (status != LDNS_STATUS_OK) {
        return {nullptr, ldns_get_errorstr_by_id(status)};
    }
    return {ldns_pkt_ptr(reply_pkt), std::nullopt};
}

} // namespace ag
