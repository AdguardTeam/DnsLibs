#include <ldns/ldns.h>

#include "ag_net_utils.h"
#include "resolver.h"
#include "upstream_dot.h"
#include "upstream_doh.h"
#include "upstream_plain.h"
#include <dns_stamp.h>


#define log_ip(l_, lvl_, ip_, fmt_, ...) lvl_##log(l_, "[{}] " fmt_, ip_, ##__VA_ARGS__)


using namespace ag;
using namespace std::chrono;


static std::optional<std::string> get_address_from_stamp(const logger &log, std::string_view url) {
    auto [stamp, error] = server_stamp::from_string(url);
    if (error.has_value()) {
        warnlog(log, "Failed to create stamp from url ({}): {}", url, error.value());
        return std::nullopt;
    }

    if (stamp.server_addr_str.empty()) {
        warnlog(log, "Got empty server address in stamp from url: {}", url);
        return std::nullopt;
    }

    switch (stamp.proto) {
    case stamp_proto_type::PLAIN:
    case stamp_proto_type::DNSCRYPT:
        return stamp.server_addr_str;
    case stamp_proto_type::DOH:
        return AG_FMT("{}{}{}", dns_over_https::SCHEME, stamp.provider_name, stamp.path);
    case stamp_proto_type::TLS:
        return stamp.provider_name;
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
    static constexpr as_entry ALLOWED_SCHEMES[] =
        {
            { dns_over_tls::SCHEME, dns_over_tls::DEFAULT_PORT },
            { dns_over_https::SCHEME, dns_over_https::DEFAULT_PORT },
            { plain_dns::TCP_SCHEME, plain_dns::DEFAULT_PORT },
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

    socket_address numeric_ip = ag::utils::str_to_socket_address(address);
    return numeric_ip.valid();
}

static std::string get_server_address(const logger &log, std::string_view address) {
    std::string result(address);
    if (ag::utils::starts_with(result, STAMP_URL_PREFIX_WITH_SCHEME)) {
        std::optional<std::string> decoded = get_address_from_stamp(log, result);
        if (decoded.has_value()) {
            dbglog(log, "Stamp '{}' decoded into '{}'", address, decoded.value());
            result = std::move(decoded.value());
        } else {
            return "";
        }
    }

    if (!check_ip_address(result)) {
        warnlog(log, "Resolver address must be a valid ip address");
        return "";
    }
    return result;
}


resolver::resolver(std::string_view resolver_address, const upstream_factory_config &upstream_config)
    : log(create_logger(AG_FMT("Resolver {}", resolver_address)))
    , resolver_address(get_server_address(this->log, resolver_address))
    , upstream_factory(upstream_config)
{}

err_string resolver::init() {
    if (this->resolver_address.empty()) {
        constexpr std::string_view err = "Failed to get server address";
        log_ip(log, err, this->resolver_address, "{}", err);
        return std::string(err);
    }

    return std::nullopt;
}

static ldns_pkt_ptr create_req(std::string_view domain_name, ldns_enum_rr_type rr_type) {
    ldns_pkt *request = ldns_pkt_query_new(
            ldns_dname_new_frm_str(std::string(domain_name).c_str()),
            rr_type, LDNS_RR_CLASS_IN, LDNS_RD);
    ldns_pkt_set_random_id(request);
    return ldns_pkt_ptr(request);
}

static std::vector<socket_address> socket_address_from_reply(const logger &log, ldns_pkt *reply, int port) {
    std::vector<socket_address> addrs;
    addrs.reserve(5);
    if (!ldns_pkt_ancount(reply)) {
        return addrs;
    }
    auto answer = ldns_pkt_answer(reply);
    for (size_t i = 0; i < ldns_rr_list_rr_count(answer); i++) {
        auto rr = ldns_rr_list_rr(answer, i);
        if (ldns_rdf *rdf = ldns_rr_a_address(rr)) {
            socket_address addr({ ldns_rdf_data(rdf), ldns_rdf_size(rdf) }, port);
            if (!addr.valid()) {
                dbglog(log, "Got invalid ip address from server: {}", addr.str());
            } else {
                addrs.emplace_back(addr);
            }
        }
    }
    return addrs;
}

resolver::result resolver::resolve(std::string_view host, int port, milliseconds timeout) const {
    log_ip(log, trace, this->resolver_address, "Resolve {}:{}", host, port);
    socket_address numeric_ip(host, port);
    if (numeric_ip.valid()) {
        return { { numeric_ip }, std::nullopt };
    }

    std::vector<socket_address> addrs;
    addrs.reserve(5);

    utils::timer timer;
    err_string error;
    ldns_pkt_ptr a_req = create_req(host, LDNS_RR_TYPE_A);

    upstream_factory::create_result factory_result = this->upstream_factory.create_upstream({this->resolver_address, {}, timeout});
    if (factory_result.error != std::nullopt) {
        std::string err = AG_FMT("Failed to create upstream: {}", factory_result.error.value());
        log_ip(log, dbg, this->resolver_address, "{}", err);
        return { {}, std::move(err) };
    }
    upstream_ptr &upstream = factory_result.upstream;

    log_ip(log, trace, this->resolver_address, "Trying to get A record for {}", host);
    auto [a_reply, a_err] = upstream->exchange(a_req.get());

    timeout -= timer.elapsed<milliseconds>();

    if (!a_err) {
        log_ip(log, trace, this->resolver_address, "Got A record for host '{}' (elapsed:{})",
            host, timer.elapsed<milliseconds>());
        auto a_addrs = socket_address_from_reply(this->log, a_reply.get(), port);
        std::move(a_addrs.begin(), a_addrs.end(), std::back_inserter(addrs));
    } else {
        error = std::move(a_err);
        log_ip(log, dbg, this->resolver_address, "Failed to get A record for host '{}': {} (elapsed:{})",
            host, error.value(), timer.elapsed<milliseconds>());
    }

    if (upstream->config().ipv6_available && timeout > MIN_TIMEOUT) {
        log_ip(log, trace, this->resolver_address, "Trying to get AAAA record for {}", host);

        ldns_pkt_ptr aaaa_req = create_req(host, LDNS_RR_TYPE_AAAA);
        auto [aaaa_reply, aaaa_err] = upstream->exchange(aaaa_req.get());
        if (!aaaa_err) {
            auto aaaa_addrs = socket_address_from_reply(this->log, aaaa_reply.get(), port);
            std::move(aaaa_addrs.begin(), aaaa_addrs.end(), std::back_inserter(addrs));
        } else {
            error = std::move(aaaa_err);
            log_ip(log, dbg, this->resolver_address, "Failed to get AAAA record for host '{}': {}",
                host, error.value());
        }
    }

    if (!error.has_value() && addrs.empty()) {
        // either an error or address list should be present
        assert(0);
        error = "No address";
    }

    return { std::move(addrs), std::move(error) };
}
