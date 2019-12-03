#include <set>
#include "bootstrapper.h"
#include <ag_utils.h>

using std::chrono::steady_clock;
using std::chrono::duration_cast;
using std::chrono::milliseconds;

static constexpr auto MIN_TIMEOUT = std::chrono::milliseconds(50);

ag::bootstrapper::ret ag::bootstrapper::get() {
    static constexpr utils::make_error<ret> make_error;
    ag::hash_set<ag::socket_address> addrs;
    utils::timer timer;
    std::scoped_lock l(m_resolved_cache_mutex);
    if (m_resolved_cache.empty()) {
        milliseconds timeout = std::chrono::seconds(5);
        for (auto &resolver : m_resolvers) {
            auto start_time = steady_clock::now().time_since_epoch();
            auto list = resolver->resolve(m_server_name, m_server_port, timeout, m_ipv6_avail);
            std::move(list.begin(), list.end(), std::inserter(addrs, addrs.begin()));
            timeout -= duration_cast<milliseconds>(steady_clock::now().time_since_epoch() - start_time);
            if (timeout <= MIN_TIMEOUT) {
                break;
            }
        }
        m_resolved_cache.assign(std::move_iterator(addrs.begin()), std::move_iterator(addrs.end()));
    }
    auto elapsed = timer.elapsed<milliseconds>();
    if (m_resolved_cache.empty()) {
        return make_error("No address", std::nullopt, m_server_name, elapsed);
    }
    return {.address = m_resolved_cache[m_round_robin_num++ % m_resolved_cache.size()],
            .server_name = m_server_name,
            .time_elapsed = elapsed};
}

ag::bootstrapper::bootstrapper(std::string_view address_string, int default_port,
        bool ipv6_avail, const std::vector<std::string> &bootstrap)
        : m_ipv6_avail(ipv6_avail) {
    std::atomic_init(&m_round_robin_num, 0);
    auto[host, port] = utils::split_host_port(address_string);
    m_server_port = std::strtol(std::string(port).c_str(), nullptr, 10);
    if (m_server_port == 0) {
        m_server_port = default_port;
    }
    m_server_name = host;
    for (auto &server : bootstrap) {
        m_resolvers.push_back(std::make_shared<resolver>(server));
    }
}

std::string ag::bootstrapper::address() {
    return m_server_name + ":" + std::to_string(m_server_port);
}

ag::resolver::resolver(std::string_view resolver_address)
        : m_resolver_address(resolver_address)
{
}

static ag::ldns_pkt_ptr create_req(std::string_view domain_name, ldns_enum_rr_type rr_type) {
    return ag::ldns_pkt_ptr(ldns_pkt_query_new(
            ldns_dname_new_frm_str(std::string(domain_name).c_str()),
            rr_type, LDNS_RR_CLASS_IN, LDNS_RD));
}

static std::vector<ag::socket_address> socket_address_from_reply(ldns_pkt *reply, int port) {
    std::vector<ag::socket_address> addrs;
    addrs.reserve(5);
    if (!ldns_pkt_ancount(reply)) {
        return addrs;
    }
    auto answer = ldns_pkt_answer(reply);
    for (size_t i = 0; i < ldns_rr_list_rr_count(answer); i++) {
        auto rr = ldns_rr_list_rr(answer, i);
        ldns_rdf *rdf = ldns_rr_a_address(rr);
        ag::uint8_view ip{ldns_rdf_data(rdf), ldns_rdf_size(rdf)};
        addrs.emplace_back(ip, port);
    }
    return addrs;
}

std::vector<ag::socket_address>
ag::resolver::resolve(std::string_view host, int port, milliseconds timeout, bool ipv6_avail) {
    ag::socket_address numeric_ip(utils::join_host_port(host, std::to_string(port)));
    if (numeric_ip.valid()) {
        return {numeric_ip};
    }
    std::vector<ag::socket_address> addrs;
    addrs.reserve(5);
    auto start_time = steady_clock::now().time_since_epoch();
    ldns_pkt_ptr a_req = create_req(host, LDNS_RR_TYPE_A);
    auto[a_reply, a_err] = ag::plain_dns(m_resolver_address, timeout, false).exchange(&*a_req);

    if (!a_err) {
        auto a_addrs = socket_address_from_reply(&*a_reply, port);
        std::move(a_addrs.begin(), a_addrs.end(), std::back_inserter(addrs));
    }
    auto finish_time = steady_clock::now().time_since_epoch();
    timeout -= duration_cast<milliseconds>(finish_time - start_time);
    if (ipv6_avail && timeout > MIN_TIMEOUT) {
        ldns_pkt_ptr aaaa_req = create_req(host, LDNS_RR_TYPE_AAAA);
        auto[aaaa_reply, aaaa_err] = ag::plain_dns(m_resolver_address, timeout, false).exchange(&*aaaa_req);
        if (!aaaa_err) {
            auto aaaa_addrs = socket_address_from_reply(&*aaaa_reply, port);
            std::move(aaaa_addrs.begin(), aaaa_addrs.end(), std::back_inserter(addrs));
        }
    }

    return addrs;
}
