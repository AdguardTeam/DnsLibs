#include <ldns/ldns.h>

#include "common/net_utils.h"
#include "dnsstamp/dns_stamp.h"

#include "resolver.h"
#include "upstream_doh.h"
#include "upstream_dot.h"
#include "upstream_plain.h"

#define log_ip(l_, lvl_, ip_, fmt_, ...) lvl_##log(l_, "[{}] " fmt_, ip_, ##__VA_ARGS__)

using namespace std::chrono;

namespace ag {

static std::optional<std::string> get_address_from_stamp(const Logger &log, std::string_view url) {
    auto [stamp, error] = ServerStamp::from_string(url);
    if (error.has_value()) {
        warnlog(log, "Failed to create stamp from url ({}): {}", url, error.value());
        return std::nullopt;
    }

    switch (stamp.proto) {
    case StampProtoType::PLAIN:
    case StampProtoType::DNSCRYPT:
        return stamp.server_addr_str;
    case StampProtoType::DOH:
    case StampProtoType::TLS:
    case StampProtoType::DOQ:
        if (!stamp.server_addr_str.empty()) {
            return stamp.server_addr_str;
        } else {
            return stamp.provider_name;
        }
    }
    warnlog(log, "Unknown stamp protocol type: {}", stamp.proto);
    assert(0);
    return std::nullopt;
}

static bool check_ip_address(std::string_view address) {
    struct as_entry {
        std::string_view scheme;
        int port;
    };
    static constexpr as_entry ALLOWED_SCHEMES[] = {
            {DotUpstream::SCHEME, DEFAULT_DOT_PORT},
            {DohUpstream::SCHEME, DEFAULT_DOH_PORT},
            {PlainUpstream::TCP_SCHEME, DEFAULT_PLAIN_PORT},
    };

    const as_entry *found = nullptr;

    for (const as_entry &entry : ALLOWED_SCHEMES) {
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
}

ErrString Resolver::init() {
    if (m_upstream_options.address.empty()) {
        constexpr std::string_view err = "Failed to get server address";
        log_ip(m_log, err, m_upstream_options.address, "{}", err);
        return std::string(err);
    }

    return std::nullopt;
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

Resolver::Result Resolver::resolve(std::string_view host, int port, Millis timeout) const {
    log_ip(m_log, trace, m_upstream_options.address, "Resolve {}:{}", host, port);
    SocketAddress numeric_ip(host, port);
    if (numeric_ip.valid()) {
        return {{numeric_ip}, std::nullopt};
    }

    std::vector<SocketAddress> addrs;
    addrs.reserve(5);

    utils::Timer timer;
    ErrString error;
    ldns_pkt_ptr a_req = create_req(host, LDNS_RR_TYPE_A);

    UpstreamOptions opts = m_upstream_options;
    opts.timeout = timeout;
    const std::string &resolver_address = opts.address;
    UpstreamFactory::CreateResult factory_result = m_upstream_factory.create_upstream(opts);
    if (factory_result.error != std::nullopt) {
        std::string err = AG_FMT("Failed to create upstream: {}", factory_result.error.value());
        log_ip(m_log, dbg, resolver_address, "{}", err);
        return {{}, std::move(err)};
    }
    UpstreamPtr &upstream = factory_result.upstream;

    log_ip(m_log, trace, resolver_address, "Trying to get A record for {}", host);
    auto [a_reply, a_err] = upstream->exchange(a_req.get());

    timeout -= timer.elapsed<Millis>();

    if (!a_err) {
        auto a_addrs = socket_address_from_reply(m_log, a_reply.get(), port);
        log_ip(m_log, trace, resolver_address, "Got {} A records for host '{}' (elapsed:{})", a_addrs.size(), host,
                timer.elapsed<Millis>());
        std::move(a_addrs.begin(), a_addrs.end(), std::back_inserter(addrs));
    } else {
        error = std::move(a_err);
        log_ip(m_log, dbg, resolver_address, "Failed to get A record for host '{}': {} (elapsed:{})", host,
                error.value(), timer.elapsed<Millis>());
    }

    if (upstream->config().ipv6_available && timeout > MIN_TIMEOUT) {
        log_ip(m_log, trace, resolver_address, "Trying to get AAAA record for {}", host);

        ldns_pkt_ptr aaaa_req = create_req(host, LDNS_RR_TYPE_AAAA);
        auto [aaaa_reply, aaaa_err] = upstream->exchange(aaaa_req.get());
        if (!aaaa_err) {
            auto aaaa_addrs = socket_address_from_reply(m_log, aaaa_reply.get(), port);
            log_ip(m_log, trace, resolver_address, "Got {} AAAA records for host '{}' (elapsed:{})", aaaa_addrs.size(),
                    host, timer.elapsed<Millis>());
            std::move(aaaa_addrs.begin(), aaaa_addrs.end(), std::back_inserter(addrs));
        } else {
            error = std::move(aaaa_err);
            log_ip(m_log, dbg, resolver_address, "Failed to get AAAA record for host '{}': {}", host, error.value());
        }
    }

    if (!error.has_value() && addrs.empty()) {
        error = AG_FMT("Could not resolve {}", host);
    }

    return {std::move(addrs), std::move(error)};
}

} // namespace ag
