#include <algorithm>

#include "bootstrapper.h"
#include <dns_stamp.h>
#include <ag_utils.h>


#define log_addr(l_, lvl_, addr_, fmt_, ...) lvl_##log(l_, "[{}] " fmt_, addr_, ##__VA_ARGS__)


using std::chrono::steady_clock;
using std::chrono::duration_cast;
using std::chrono::milliseconds;

static constexpr int64_t RESOLVE_TRYING_INTERVAL_MS = 7000;
static constexpr int64_t TEMPORARY_DISABLE_INTERVAL_MS = 7000;

// For each resolver a half of time out is given for a try. If one fails, it's moved to the end
// of the list to give it a chance in the future.
//
// Note: in case of success MUST always return vector of addresses in address field of result
ag::bootstrapper::resolve_result ag::bootstrapper::resolve() {
    if (socket_address addr(m_server_name, m_server_port); addr.valid()) {
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
        resolver::result result = resolver->resolve(m_server_name, m_server_port, try_timeout);
        if (result.error.has_value()) {
            log_addr(m_log, dbg, m_server_name, "Failed to resolve host: {}", result.error.value());
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
            log_addr(m_log, dbg, m_server_name, "Stop resolving loop as timeout reached ({})", m_timeout);
            break;
        }
    }

    if (m_log->should_log((spdlog::level::level_enum)DEBUG)) {
        for (const socket_address &a : addrs) {
            log_addr(m_log, dbg, m_server_name, "Resolved address: {}", a.str());
        }
    }

    milliseconds elapsed = whole_resolve_timer.elapsed<milliseconds>();

    std::vector<socket_address> addresses(std::move_iterator(addrs.begin()), std::move_iterator(addrs.end()));
    return { std::move(addresses), m_server_name, elapsed, std::move(error) };
}

ag::err_string ag::bootstrapper::temporary_disabler_check() {
    using namespace std::chrono;
    if (m_resolve_fail_times_ms.first) {
        if (int64_t tries_timeout_ms = m_resolve_fail_times_ms.first + RESOLVE_TRYING_INTERVAL_MS;
                m_resolve_fail_times_ms.second > tries_timeout_ms) {
            auto now_ms = duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
            if (int64_t disabled_for_ms = now_ms - tries_timeout_ms,
                        remaining_ms = TEMPORARY_DISABLE_INTERVAL_MS - disabled_for_ms;
                    remaining_ms > 0) {
                return AG_FMT("Bootstrapping this server is disabled for {}ms, too many failures", remaining_ms);
            } else {
                m_resolve_fail_times_ms.first = 0;
            }
        }
    }
    return std::nullopt;
}

void ag::bootstrapper::temporary_disabler_update(const err_string &error) {
    using namespace std::chrono;
    if (error) {
        auto now_ms = duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
        m_resolve_fail_times_ms.second = now_ms;
        if (!m_resolve_fail_times_ms.first) {
            m_resolve_fail_times_ms.first = m_resolve_fail_times_ms.second;
        }
    } else {
        m_resolve_fail_times_ms.first = 0;
    }
}


ag::bootstrapper::resolve_result ag::bootstrapper::get() {
    std::scoped_lock l(m_resolved_cache_mutex);
    if (!m_resolved_cache.empty()) {
        return { m_resolved_cache, m_server_name, milliseconds(0), std::nullopt };
    } else if (auto error = temporary_disabler_check()) {
        return { {}, m_server_name, milliseconds(0), error };
    }

    resolve_result result = resolve();
    assert(result.error.has_value() == result.addresses.empty());
    temporary_disabler_update(result.error);
    m_resolved_cache = result.addresses;
    return result;
}

void ag::bootstrapper::remove_resolved(const socket_address &addr) {
    std::scoped_lock l(m_resolved_cache_mutex);
    m_resolved_cache.erase(std::remove(m_resolved_cache.begin(), m_resolved_cache.end(), addr),
        m_resolved_cache.end());
}

static std::vector<ag::resolver_ptr> create_resolvers(const ag::logger &log, const ag::bootstrapper::params &p) {
    std::vector<ag::resolver_ptr> resolvers;
    resolvers.reserve(p.bootstrap.size());

    ag::upstream_options opts{};
    opts.outbound_interface = p.outbound_interface;
    for (const std::string &server : p.bootstrap) {
        opts.address = server;
        ag::resolver_ptr resolver = std::make_unique<ag::resolver>(opts, p.upstream_config);
        if (ag::err_string err = resolver->init(); !err.has_value()) {
            resolvers.emplace_back(std::move(resolver));
        } else {
            log_addr(log, warn, p.address_string, "Failed to create resolver '{}': {}", server, err.value());
        }
    }

    if (p.bootstrap.empty() && !ag::utils::str_to_socket_address(p.address_string).valid()) {
        log_addr(log, warn, p.address_string, "Got empty or invalid list of servers for bootstrapping");
    }

    return resolvers;
}

ag::bootstrapper::bootstrapper(const params &p)
        : m_log(create_logger(__func__))
        , m_timeout(p.timeout)
        , m_resolvers(create_resolvers(m_log, p))
{
    auto[host, port] = utils::split_host_port(p.address_string);
    m_server_port = std::strtol(std::string(port).c_str(), nullptr, 10);
    if (m_server_port == 0) {
        m_server_port = p.default_port;
    }
    m_server_name = host;
}

ag::err_string ag::bootstrapper::init() {
    if (m_resolvers.empty() && !socket_address(m_server_name, m_server_port).valid()) {
        return "Failed to create any resolver";
    }

    return std::nullopt;
}

std::string ag::bootstrapper::address() const {
    return AG_FMT("{}:{}", m_server_name, m_server_port);
}
