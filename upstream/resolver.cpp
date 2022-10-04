#include <ldns/ldns.h>

#include "common/net_utils.h"
#include "dns/dnsstamp/dns_stamp.h"

#include "resolver.h"
#include "upstream_doh.h"
#include "upstream_dot.h"
#include "upstream_plain.h"

#define log_ip(l_, lvl_, ip_, fmt_, ...) lvl_##log(l_, "[{}] " fmt_, ip_, ##__VA_ARGS__)

using namespace std::chrono;

namespace ag::dns {

static std::optional<std::string> get_address_from_stamp(const Logger &log, std::string_view url) {
    auto stamp = ServerStamp::from_string(url);
    if (stamp.has_error()) {
        warnlog(log, "Failed to create stamp from url ({}): {}", url, stamp.error()->str());
        return std::nullopt;
    }

    switch (stamp->proto) {
    case StampProtoType::PLAIN:
    case StampProtoType::DNSCRYPT:
        return stamp->server_addr_str;
    case StampProtoType::DOH:
    case StampProtoType::TLS:
    case StampProtoType::DOQ:
        if (!stamp->server_addr_str.empty()) {
            return stamp->server_addr_str;
        } else {
            return stamp->provider_name;
        }
    }
    warnlog(log, "Unknown stamp protocol type: {}", stamp->proto);
    assert(0);
    return std::nullopt;
}

static bool check_ip_address(std::string_view address) {
    struct AllowedScheme {
        std::string_view scheme;
        int port;
    };
    static constexpr AllowedScheme ALLOWED_SCHEMES[] = {
            {DotUpstream::SCHEME, DEFAULT_DOT_PORT},
            {DohUpstream::SCHEME_HTTPS, DEFAULT_DOH_PORT},
            {DohUpstream::SCHEME_H3, DEFAULT_DOH_PORT},
            {PlainUpstream::TCP_SCHEME, DEFAULT_PLAIN_PORT},
    };

    const AllowedScheme *found = nullptr;

    for (const AllowedScheme &entry : ALLOWED_SCHEMES) {
        if (utils::starts_with(address, entry.scheme)) {
            found = &entry;
            break;
        }
    }

    if (found != nullptr) {
        address.remove_prefix(found->scheme.length());
        if (size_t pos = address.find('/'); pos != address.npos) {
            address.remove_suffix(address.length() - pos);
        }
    }

    SocketAddress numeric_ip = ag::utils::str_to_socket_address(address);
    return numeric_ip.valid();
}

static std::string get_server_address(const Logger &log, std::string_view address) {
    std::string result(address);
    if (ag::utils::starts_with(result, STAMP_URL_PREFIX_WITH_SCHEME)) {
        std::optional<std::string> decoded = get_address_from_stamp(log, result);
        if (decoded.has_value()) {
            dbglog(log, "Stamp '{}' decoded into '{}'", address, decoded.value());
            if (!check_ip_address(*decoded)) {
                warnlog(log, "Resolver address must be a valid ip address");
                return "";
            }
        } else {
            warnlog(log, "Failed to parse DNS stamp");
            return "";
        }
    } else if (!check_ip_address(result)) {
        warnlog(log, "Resolver address must be a valid ip address");
        return "";
    }
    return result;
}

Resolver::Resolver(UpstreamOptions options, const UpstreamFactoryConfig &upstream_config)
        : m_log(AG_FMT("Resolver {}", options.address))
        , m_upstream_factory(upstream_config)
        , m_upstream_options(std::move(options)) {
    m_upstream_options.address = get_server_address(m_log, m_upstream_options.address);
    m_shutdown_guard = std::make_shared<bool>(true);
}

Error<Resolver::ResolverError> Resolver::init() {
    if (m_upstream_options.address.empty()) {
        constexpr std::string_view err = "Failed to get server address";
        log_ip(m_log, err, m_upstream_options.address, "{}", err);
        return make_error(ResolverError::AE_INVALID_ADDRESS);
    }

    return {};
}

static ldns_pkt_ptr create_req(std::string_view domain_name, ldns_enum_rr_type rr_type) {
    ldns_pkt *request = ldns_pkt_query_new(
            ldns_dname_new_frm_str(std::string(domain_name).c_str()), rr_type, LDNS_RR_CLASS_IN, LDNS_RD);
    ldns_pkt_set_random_id(request);
    return ldns_pkt_ptr(request);
}

static std::vector<SocketAddress> socket_address_from_reply(const Logger &log, ldns_pkt *reply, int port) {
    std::vector<SocketAddress> addrs;
    addrs.reserve(5);
    if (!ldns_pkt_ancount(reply)) {
        return addrs;
    }
    auto answer = ldns_pkt_answer(reply);
    for (size_t i = 0; i < ldns_rr_list_rr_count(answer); i++) {
        auto rr = ldns_rr_list_rr(answer, i);
        if (ldns_rdf *rdf = ldns_rr_a_address(rr)) {
            SocketAddress addr({ldns_rdf_data(rdf), ldns_rdf_size(rdf)}, port);
            if (!addr.valid()) {
                dbglog(log, "Got invalid ip address from server: {}", addr.str());
            } else {
                addrs.emplace_back(addr);
            }
        }
    }
    return addrs;
}

coro::Task<Resolver::Result> Resolver::resolve(std::string_view host, int port, Millis timeout) const {
    log_ip(m_log, trace, m_upstream_options.address, "Resolve {}:{}", host, port);
    SocketAddress numeric_ip(host, port);
    if (numeric_ip.valid()) {
        co_return std::vector<SocketAddress>{numeric_ip};
    }

    std::vector<SocketAddress> addrs;
    addrs.reserve(5);

    utils::Timer timer;
    Error<ResolverError> error;
    ldns_pkt_ptr a_req = create_req(host, LDNS_RR_TYPE_A);

    UpstreamOptions opts = m_upstream_options;
    opts.timeout = timeout;
    const std::string &resolver_address = opts.address;
    UpstreamFactory::CreateResult factory_result = m_upstream_factory.create_upstream(opts);
    if (factory_result.has_error()) {
        std::string err = AG_FMT("Failed to create upstream: {}", factory_result.error()->str());
        log_ip(m_log, dbg, resolver_address, "{}", factory_result.error()->str());
        co_return make_error(ResolverError::AE_UPSTREAM_INIT_FAILED, factory_result.error());
    }
    UpstreamPtr &upstream = factory_result.value();

    log_ip(m_log, trace, resolver_address, "Trying to get A/AAAA records for {}", host);
    ldns_pkt_ptr aaaa_req;
    if (upstream->config().ipv6_available) {
        aaaa_req = create_req(host, LDNS_RR_TYPE_AAAA);
    }
    std::weak_ptr<bool> shutdown_guard = m_shutdown_guard;
    auto replies = upstream->config().ipv6_available
            ? co_await parallel::all_of<Upstream::ExchangeResult>(upstream->exchange(a_req.get()), upstream->exchange(aaaa_req.get()))
            : co_await parallel::all_of<Upstream::ExchangeResult>(upstream->exchange(a_req.get()));
    timeout -= timer.elapsed<Millis>();
    if (shutdown_guard.expired()) {
        co_return make_error(ResolverError::AE_SHUTTING_DOWN);
    }

    Error<ResolverError> last_error{};
    for (auto &reply : replies) {
        if (reply.has_error()) {
            log_ip(m_log, dbg, resolver_address, "Failed to talk to upstream for host '{}' (elapsed:{}):\n{}", host, timer.elapsed<Millis>(), reply.error()->str());
            last_error = make_error(ResolverError::AE_EXCHANGE_FAILED, AG_FMT("Could not resolve {}", host), reply.error());
            continue;
        }
        auto reply_addrs = socket_address_from_reply(m_log, reply->get(), port);
        std::move(reply_addrs.begin(), reply_addrs.end(), std::back_inserter(addrs));
    }

    if (addrs.empty()) {
        error = last_error ? last_error : make_error(ResolverError::AE_EMPTY_ADDRS, AG_FMT("Could not resolve {}", host));
    }

    if (error) {
        co_return error;
    } else {
        co_return addrs;
    }
}

Resolver::~Resolver() {
    tracelog(m_log, "");
}

} // namespace ag::dns
