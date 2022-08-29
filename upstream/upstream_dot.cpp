#include <openssl/x509v3.h>
#include <openssl/ssl.h>

#include "common/defs.h"
#include "common/utils.h"

#include "dns_framed.h"
#include "upstream_dot.h"

using std::chrono::milliseconds;
using std::chrono::seconds;
using std::chrono::duration_cast;

static constexpr auto DOT_IDLE_TIMEOUT = seconds(30);

namespace ag::dns {

#define log_conn(l_, lvl_, conn_, fmt_, ...) lvl_##log(l_, "[id={} addr={}] " fmt_, conn_->m_id, conn_->address_str(), ##__VA_ARGS__)
#define tracelog_id(l_, pkt_, fmt_, ...) tracelog((l_), "[{}] " fmt_, ldns_pkt_id(pkt_), ##__VA_ARGS__)

class DotConnection;

using DotConnectionPtr = std::shared_ptr<DotConnection>;

class DotConnection : public DnsFramedConnection {
public:
    DotConnection(const ConstructorAccess &access, EventLoop &loop, const ConnectionPoolPtr &pool,
            const std::string &address_str)
            : DnsFramedConnection(access, loop, pool, address_str) {
        this->m_idle_timeout = DOT_IDLE_TIMEOUT;
    }

    static DotConnectionPtr create(EventLoop &loop, const ConnectionPoolPtr &pool, const std::string &address_str) {
        return std::make_shared<DotConnection>(ConstructorAccess{}, loop, pool, address_str);
    }

    coro::Task<void> co_connect() {
        auto weak_self = weak_from_this();
        auto *dot_upstream = (DotUpstream *) m_pool.lock()->upstream();
        assert(dot_upstream != nullptr);
        auto result = co_await dot_upstream->m_bootstrapper->get();
        if (weak_self.expired()) {
            co_return;
        }
        if (result.error) {
            auto &err = *result.error;
            log_conn(m_log, err, this, "Failed to bootstrap: {}", err.str());
            this->on_close(make_error(DE_BOOTSTRAP_ERROR, result.error));
        } else {
            m_result = std::move(result);
            assert(!m_result.addresses.empty());

            static const std::string DOT_ALPN = "dot";

            SocketAddress &addr = m_result.addresses[0];
            Millis timeout;
            if (auto *upstream = (DotUpstream *) m_pool.lock()->upstream()) {
                m_stream = upstream->make_secured_socket(utils::TP_TCP,
                        SocketFactory::SecureSocketParameters{
                                .session_cache = &upstream->m_tls_session_cache,
                                .server_name = m_result.server_name.empty() ? addr.host_str() : m_result.server_name,
                                .alpn = {DOT_ALPN},
                        });
                timeout = upstream->options().timeout;
            } else {
                on_close(make_error(DE_SHUTTING_DOWN, "Shutting down"));
            }
            dbglog(m_log, "{}", addr.str());
            m_address = addr;
            auto err = m_stream->connect({
                    &m_loop,
                    addr,
                    {on_connected, on_read, on_close, this},
                    timeout,
            });
            if (err) {
                log_conn(m_log, err, this, "Failed to start connect: {}", err->str());
                on_close(this, err);
            }
        }
        co_return;
    }

    void connect() override {
        coro::run_detached(this->co_connect());
    }

    void finish_request(uint16_t request_id, Reply &&reply) override {
        if (reply.has_error()) {
            if (reply.error()->value() == DE_SOCKET_ERROR
                    || reply.error()->value() == DE_TIMED_OUT
                    || reply.error()->value() == DE_CONNECTION_CLOSED) {
                if (auto pool = m_pool.lock()) {
                    if (auto *upstream = (DotUpstream *) pool->upstream()) {
                        upstream->m_bootstrapper->remove_resolved(m_address);
                    }
                }
            }
        }
        this->DnsFramedConnection::finish_request(request_id, std::move(reply));
    }

    Bootstrapper::ResolveResult m_result;
};

static std::optional<std::string> get_resolved_ip(const Logger &log, const IpAddress &addr) {
    if (std::holds_alternative<std::monostate>(addr)) {
        return std::nullopt;
    }

    SocketAddress parsed;
    if (const Ipv4Address *ipv4 = std::get_if<Ipv4Address>(&addr); ipv4 != nullptr) {
        parsed = SocketAddress({ipv4->data(), ipv4->size()}, DEFAULT_DOT_PORT);
    } else if (const Ipv6Address *ipv6 = std::get_if<Ipv6Address>(&addr); ipv6 != nullptr) {
        parsed = SocketAddress({ipv6->data(), ipv6->size()}, DEFAULT_DOT_PORT);
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
    assert(utils::starts_with(url, DotUpstream::SCHEME));
    url.remove_prefix(DotUpstream::SCHEME.length());
    url = url.substr(0, url.find('/'));
    return url;
}

static std::string_view get_host_name(std::string_view url) {
    return utils::trim(utils::split_host_port(strip_dot_url(url)).first);
}

static BootstrapperPtr create_bootstrapper(const Logger &log, const UpstreamOptions &opts,
                                            const UpstreamFactoryConfig &config) {
    std::string_view address;
    int port = 0;

    std::optional<std::string> resolved = get_resolved_ip(log, opts.resolved_server_ip);
    if (resolved.has_value()) {
        address = resolved.value();
    } else {
        auto[host, port_str] = utils::split_host_port(strip_dot_url(opts.address));
        address = host;
        if (!port_str.empty()) {
            port = std::strtol(std::string(port_str).c_str(), nullptr, 10);
        }
    }

    return std::make_unique<Bootstrapper>(Bootstrapper::Params{address, (port == 0) ? DEFAULT_DOT_PORT : port,
            opts.bootstrap, opts.timeout, config, opts.outbound_interface});
}

DotUpstream::DotUpstream(const UpstreamOptions &opts, const UpstreamFactoryConfig &config)
        : Upstream(opts, config)
        , m_log("DOT upstream")
        , m_server_name(get_host_name(opts.address))
        , m_tls_session_cache(opts.address)
{}

Error<Upstream::InitError> DotUpstream::init() {
    if (auto hostname = get_host_name(this->m_options.address);
            hostname.empty()) {
        return make_error(InitError::AE_EMPTY_SERVER_NAME);
    } else { // NOLINT: clang-tidy is wrong here
        if (this->m_options.bootstrap.empty()
                && std::holds_alternative<std::monostate>(this->m_options.resolved_server_ip)
                && !SocketAddress(hostname, 0).valid()) {
            return make_error(InitError::AE_EMPTY_BOOTSTRAP);
        }
    }

    m_pool = std::make_shared<ConnectionPool<DotConnection>>(config().loop, shared_from_this(), 10);

    m_bootstrapper = create_bootstrapper(m_log, this->m_options, this->m_config);
    if (auto err = m_bootstrapper->init()) {
        return make_error(InitError::AE_BOOTSTRAPPER_INIT_FAILED, err);
    }

    return {};
}

DotUpstream::~DotUpstream() = default;

coro::Task<Upstream::ExchangeResult> DotUpstream::exchange(ldns_pkt *request_pkt, const DnsMessageInfo *info) {
    ldns_buffer_ptr buffer{ldns_buffer_new(REQUEST_BUFFER_INITIAL_CAPACITY)};
    ldns_status status = ldns_pkt2buffer_wire(&*buffer, request_pkt);
    if (status != LDNS_STATUS_OK) {
        co_return make_error(DE_ENCODE_ERROR, ldns_get_errorstr_by_id(status));
    }

    AllocatedPtr<char> domain;
    if (ldns_rr *question = ldns_rr_list_rr(ldns_pkt_question(request_pkt), 0)) {
        domain = AllocatedPtr<char>(ldns_rdf2str(ldns_rr_owner(question)));
        tracelog_id(m_log, request_pkt, "Querying for a domain: {}", domain.get());
    }

    milliseconds timeout = m_options.timeout;

    Uint8View buf{ ldns_buffer_begin(buffer.get()), ldns_buffer_position(buffer.get()) };
    tracelog_id(m_log, request_pkt, "Sending request for a domain: {}", domain ? domain.get() : "(unknown)");
    Connection::Reply reply = co_await m_pool->perform_request(buf, timeout);
    if (reply.has_error()) {
        co_return reply.error();
    }
    ldns_pkt *reply_pkt = nullptr;
    status = ldns_wire2pkt(&reply_pkt, reply.value().data(), reply.value().size());
    if (status != LDNS_STATUS_OK) {
        co_return make_error(DE_DECODE_ERROR, ldns_get_errorstr_by_id(status));
    }
    co_return ldns_pkt_ptr{reply_pkt};
}

} // namespace ag::dns
