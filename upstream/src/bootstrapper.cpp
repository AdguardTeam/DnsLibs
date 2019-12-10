#include "bootstrapper.h"
#include <dns_stamp.h>
#include <ag_utils.h>


using std::chrono::steady_clock;
using std::chrono::duration_cast;
using std::chrono::milliseconds;


// For each resolver a half of time out is given for a try. If one fails, it's moved to the end
// of the list to give it a chance in the future.
//
// Note: in case of success MUST always return vector of addresses in address field of result
ag::bootstrapper::resolve_result ag::bootstrapper::resolve() {
    if (socket_address addr(AG_FMT("{}:{}", m_server_name, m_server_port)); addr.valid()) {
        return { { addr }, m_server_name, milliseconds(0), std::nullopt };
    }

    if (m_resolvers.empty()) {
        return { {}, m_server_name, milliseconds(0), "Empty bootstrap list" };
    }

    ag::hash_set<ag::socket_address> addrs;
    utils::timer whole_resolve_timer;
    milliseconds timeout = m_timeout;
    err_string error;

    for (size_t tried = 0, failed = 0, curr = 0;
            tried < m_resolvers.size();
            ++tried, curr = tried - failed) {
        const resolver_ptr &resolver = m_resolvers[curr];
        utils::timer single_resolve_timer;
        milliseconds try_timeout = std::max(timeout / 2, resolver::MIN_TIMEOUT);
        resolver::result result = resolver->resolve(m_server_name, m_server_port, try_timeout, m_ipv6_avail);
        if (result.error.has_value()) {
            dbglog(m_log, "Failed to resolve host '{}': {}", m_server_name, result.error.value());
            std::rotate(m_resolvers.begin() + curr, m_resolvers.begin() + curr + 1, m_resolvers.end());
            ++failed;
            if (addrs.empty()) {
                error = AG_FMT("{}{}\n", error.has_value() ? error.value() : "", result.error.value());
            }
        } else {
            std::move(result.addresses.begin(), result.addresses.end(), std::inserter(addrs, addrs.begin()));
            error.reset();
        }
        timeout -= single_resolve_timer.elapsed<milliseconds>();
        if (timeout <= resolver::MIN_TIMEOUT) {
            dbglog(m_log, "Stop resolving loop as timeout reached ({})", m_timeout);
            break;
        }
    }

    milliseconds elapsed = whole_resolve_timer.elapsed<milliseconds>();

    std::vector<socket_address> addresses(std::move_iterator(addrs.begin()), std::move_iterator(addrs.end()));
    return { std::move(addresses), m_server_name, elapsed, std::move(error) };
}

ag::bootstrapper::resolve_result ag::bootstrapper::get() {
    resolve_result result = get_all();
    if (!result.error.has_value()) {
        assert(!result.addresses.empty());
        result.addresses.erase(result.addresses.begin() + 1, result.addresses.end());
    }

    return result;
}

ag::bootstrapper::resolve_result ag::bootstrapper::get_all() {
    std::scoped_lock l(m_resolved_cache_mutex);
    if (!m_resolved_cache.empty()) {
        return { m_resolved_cache, m_server_name, milliseconds(0), std::nullopt };
    }

    resolve_result result = resolve();
    assert(result.error.has_value() == result.addresses.empty());
    return result;
}

static std::vector<ag::resolver_ptr> create_resolvers(const ag::logger &log, const ag::bootstrapper::params &p) {
    std::vector<ag::resolver_ptr> resolvers;
    resolvers.reserve(p.bootstrap.size());

    for (const std::string &server : p.bootstrap) {
        resolvers.push_back(std::make_unique<ag::resolver>(server, p.upstream_config));
    }

    if (p.bootstrap.empty() && !ag::socket_address(p.address_string).valid()) {
        warnlog(log, "Got empty list of the servers for bootstrapping");
    }

    return resolvers;
}

ag::bootstrapper::bootstrapper(const params &p)
        : m_log(create_logger(AG_FMT("Bootstrapper {}", p.address_string)))
        , m_timeout(p.timeout)
        , m_round_robin_num({0})
        , m_ipv6_avail(p.ipv6_avail)
        , m_resolvers(create_resolvers(m_log, p))
{
    auto[host, port] = utils::split_host_port(p.address_string);
    m_server_port = std::strtol(std::string(port).c_str(), nullptr, 10);
    if (m_server_port == 0) {
        m_server_port = p.default_port;
    }
    m_server_name = host;
}

std::string ag::bootstrapper::address() const {
    return AG_FMT("{}:{}", m_server_name, m_server_port);
}
