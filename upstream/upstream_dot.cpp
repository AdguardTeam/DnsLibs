#include "upstream_dot.h"

#include <memory>

#include <fmt/std.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include "common/defs.h"
#include "common/utils.h"
#include "dns/common/dns_defs.h"

#include "bootstrapped_connection.h"

using std::chrono::milliseconds;
using std::chrono::seconds;

static constexpr auto DOT_IDLE_TIMEOUT = seconds(30);

namespace ag::dns {

#define tracelog_id(l_, pkt_, fmt_, ...) tracelog((l_), "[{}] " fmt_, ldns_pkt_id(pkt_), ##__VA_ARGS__)

class DotConnection;

using DotConnectionPtr = std::shared_ptr<DotConnection>;

class DotConnection : public BootstrappedFramedConnection {
public:
    DotConnection(const ConstructorAccess &access, EventLoop &loop, const ConnectionPoolPtr &pool,
            const std::string &address_str)
            : BootstrappedFramedConnection(access, loop, pool, address_str) {
        m_idle_timeout = DOT_IDLE_TIMEOUT;
    }

    static DotConnectionPtr create(EventLoop &loop, const ConnectionPoolPtr &pool, const std::string &address_str) {
        return std::make_shared<DotConnection>(ConstructorAccess{}, loop, pool, address_str);
    }

private:
    SocketFactory::SocketPtr make_stream(const std::shared_ptr<Upstream> &upstream) override {
        static const std::string DOT_ALPN = "dot";
        auto dot_upstream = std::static_pointer_cast<DotUpstream>(upstream);
        return dot_upstream->make_secured_socket(utils::TP_TCP,
                SocketFactory::SecureSocketParameters{
                        .session_cache = &dot_upstream->m_tls_session_cache,
                        .server_name = std::string(dot_upstream->m_url.get_hostname()),
                        .alpn = {DOT_ALPN},
                        .fingerprints = dot_upstream->m_fingerprints,
                        .enable_post_quantum = dot_upstream->m_options.enable_post_quantum_cryptography,
                });
    }

    Bootstrapper *bootstrapper(const std::shared_ptr<Upstream> &upstream) override {
        return std::static_pointer_cast<DotUpstream>(upstream)->m_bootstrapper.get();
    }

    AddressVariant no_bootstrap_address(const std::shared_ptr<Upstream> &upstream) override {
        auto dot_upstream = std::static_pointer_cast<DotUpstream>(upstream);
        return NamePort{std::string(dot_upstream->m_url.get_hostname()), dot_upstream->m_port};
    }
};

static Result<BootstrapperPtr, Upstream::InitError> create_bootstrapper(const UpstreamOptions &opts,
        const UpstreamFactoryConfig &config, const ada::url_aggregator url, uint16_t port) {
    std::string address;

    if (auto resolved = SocketAddress(opts.resolved_server_ip, DEFAULT_DOT_PORT); resolved.valid()) {
        address = resolved.host_str(/*ipv6_brackets*/ true);
    } else {
        address = url.get_hostname();
    }

    return std::make_unique<Bootstrapper>(
            Bootstrapper::Params{address, port, opts.bootstrap, config.timeout, config, opts.outbound_interface});
}

DotUpstream::DotUpstream(
        const UpstreamOptions &opts, const UpstreamFactoryConfig &config, std::vector<CertFingerprint> fingerprints)
        : Upstream(opts, config)
        , m_log("DOT upstream")
        , m_tls_session_cache(opts.address)
        , m_fingerprints(std::move(fingerprints)) {
}

Error<Upstream::InitError> DotUpstream::init() {
    auto error = this->init_url_port(
            /*allow_creds*/ false, /*allow_path*/ false, DEFAULT_DOT_PORT, /*host_to_lowercase*/ false);
    if (error) {
        return error;
    }

    if (const auto *oproxy_settings = config().socket_factory->get_outbound_proxy_settings();
            !oproxy_settings || !oproxy_protocol_supports_hostname(oproxy_settings->protocol)) {
        if (m_options.bootstrap.empty() && std::holds_alternative<std::monostate>(m_options.resolved_server_ip)
                && !SocketAddress(m_url.get_hostname(), m_port).valid()) {
            return make_error(InitError::AE_EMPTY_BOOTSTRAP);
        }

        auto create_result = create_bootstrapper(m_options, m_config, m_url, m_port);
        if (create_result.has_error()) {
            return make_error(InitError::AE_BOOTSTRAPPER_INIT_FAILED, create_result.error());
        }
        m_bootstrapper = std::move(create_result.value());
        if (auto err = m_bootstrapper->init()) {
            return make_error(InitError::AE_BOOTSTRAPPER_INIT_FAILED, err);
        }
    }

    m_pool = std::make_shared<ConnectionPool<DotConnection>>(config().loop, shared_from_this(), 10);

    return {};
}

DotUpstream::~DotUpstream() = default;

coro::Task<Upstream::ExchangeResult> DotUpstream::exchange(const ldns_pkt *request_pkt, const DnsMessageInfo *info) {
    ldns_buffer_ptr buffer{ldns_buffer_new(REQUEST_BUFFER_INITIAL_CAPACITY)};
    ldns_status status = ldns_pkt2buffer_wire(&*buffer, request_pkt);
    if (status != LDNS_STATUS_OK) {
        co_return make_error(DnsError::AE_ENCODE_ERROR, ldns_get_errorstr_by_id(status));
    }

    AllocatedPtr<char> domain;
    if (ldns_rr *question = ldns_rr_list_rr(ldns_pkt_question(request_pkt), 0)) {
        domain = AllocatedPtr<char>(ldns_rdf2str(ldns_rr_owner(question)));
        tracelog_id(m_log, request_pkt, "Querying for a domain: {}", domain.get());
    }

    milliseconds timeout = m_config.timeout;

    Uint8View buf{ldns_buffer_begin(buffer.get()), ldns_buffer_position(buffer.get())};
    tracelog_id(m_log, request_pkt, "Sending request for a domain: {}", domain ? domain.get() : "(unknown)");
    std::weak_ptr<ConnectionPoolBase> guard = m_pool;
    Connection::Reply reply = co_await m_pool->perform_request(buf, timeout);
    if (guard.expired()) {
        co_return make_error(DnsError::AE_SHUTTING_DOWN);
    }
    if (reply.has_error()) {
        co_return reply.error();
    }
    ldns_pkt *reply_pkt = nullptr;
    status = ldns_wire2pkt(&reply_pkt, reply.value().data(), reply.value().size());
    if (status != LDNS_STATUS_OK) {
        co_return make_error(DnsError::AE_DECODE_ERROR, ldns_get_errorstr_by_id(status));
    }
    co_return ldns_pkt_ptr{reply_pkt};
}

} // namespace ag::dns
