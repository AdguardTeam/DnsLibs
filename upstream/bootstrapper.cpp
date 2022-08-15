#include <algorithm>
#include <cassert>

#include "common/parallel.h"
#include "common/utils.h"
#include "dns/dnsstamp/dns_stamp.h"

#include "bootstrapper.h"

#define log_addr(l_, lvl_, addr_, fmt_, ...) lvl_##log(l_, "[{}] " fmt_, addr_, ##__VA_ARGS__)

namespace ag::dns {

using std::chrono::duration_cast;

static constexpr int64_t RESOLVE_TRYING_INTERVAL_MS = 7000;
static constexpr int64_t TEMPORARY_DISABLE_INTERVAL_MS = 7000;

// For each resolver a half of time out is given for a try. If one fails, it's moved to the end
// of the list to give it a chance in the future.
//
// Note: in case of success MUST always return vector of addresses in address field of result
coro::Task<Bootstrapper::ResolveResult> Bootstrapper::resolve() {
    if (SocketAddress addr(m_server_name, m_server_port); addr.valid()) {
        co_return {{addr}, m_server_name, Millis(0), {}};
    }

    if (m_resolvers.empty()) {
        co_return {{}, m_server_name, Millis(0), make_error(BootstrapperError::AE_EMPTY_LIST)};
    }

    HashSet<SocketAddress> addrs;
    utils::Timer whole_resolve_timer;
    Millis timeout = m_timeout;
    Error<Resolver::ResolverError> error;

    auto aw = parallel::any_of_cond<Resolver::Result>([log = m_log, server_name = m_server_name, &error](const Resolver::Result &result){
        if (result.has_error()) {
            log_addr(log, dbg, server_name, "Failed to resolve host: {}", result.error()->str());
            error = result.error();
            return false;
        }
        return true;
    });
    for (auto &resolver : m_resolvers) {
        aw.add(resolver->resolve(m_server_name, m_server_port, timeout));
    }
    std::string server_name = m_server_name;
    std::weak_ptr<bool> shutdown_guard = m_shutdown_guard;
    std::optional<Resolver::Result> res = co_await aw;
    if (shutdown_guard.expired()) {
        co_return Bootstrapper::ResolveResult{
            .server_name = server_name,
            .error = make_error(BootstrapperError::AE_SHUTTING_DOWN)
        };
    }
    if (res.has_value()) {
        std::move(res->value().begin(), res->value().end(), std::inserter(addrs, addrs.begin()));
        error.reset();
    }

    if (m_log.is_enabled(LogLevel::LOG_LEVEL_DEBUG)) {
        for (const SocketAddress &a : addrs) {
            log_addr(m_log, dbg, m_server_name, "Resolved address: {}", a.str());
        }
    }

    auto elapsed = whole_resolve_timer.elapsed<Millis>();

    std::vector<SocketAddress> addresses(std::move_iterator(addrs.begin()), std::move_iterator(addrs.end()));
    co_return {std::move(addresses), m_server_name, elapsed,
            error ? error->value() == Resolver::ResolverError::AE_SHUTTING_DOWN
                            ? make_error(BootstrapperError::AE_SHUTTING_DOWN, error)
                            : make_error(BootstrapperError::AE_RESOLVE_FAILED, error)
                  : nullptr};
}

ErrString Bootstrapper::temporary_disabler_check() {
    using namespace std::chrono;
    if (m_resolve_fail_times_ms.first) {
        if (int64_t tries_timeout_ms = m_resolve_fail_times_ms.first + RESOLVE_TRYING_INTERVAL_MS;
                m_resolve_fail_times_ms.second > tries_timeout_ms) {
            auto now_ms = duration_cast<Millis>(steady_clock::now().time_since_epoch()).count();
            if (int64_t disabled_for_ms = now_ms - tries_timeout_ms,
                    remaining_ms = TEMPORARY_DISABLE_INTERVAL_MS - disabled_for_ms;
                    remaining_ms > 0) {
                return AG_FMT("Disabled for {}ms", remaining_ms);
            }
            m_resolve_fail_times_ms.first = 0;
        }
    }
    return std::nullopt;
}

void Bootstrapper::temporary_disabler_update(bool fail) {
    using namespace std::chrono;
    if (fail) {
        auto now_ms = duration_cast<Millis>(steady_clock::now().time_since_epoch()).count();
        m_resolve_fail_times_ms.second = now_ms;
        if (!m_resolve_fail_times_ms.first) {
            m_resolve_fail_times_ms.first = m_resolve_fail_times_ms.second;
        }
    } else {
        m_resolve_fail_times_ms.first = 0;
    }
}

coro::Task<Bootstrapper::ResolveResult> Bootstrapper::get() {
    if (!m_resolved_cache.empty()) {
        co_return {m_resolved_cache, m_server_name, Millis(0), {}};
    } else if (auto error = temporary_disabler_check()) {
        co_return {{}, m_server_name, Millis(0), make_error(BootstrapperError::AE_TEMPORARY_DISABLED, *error)};
    }

    ResolveResult result = co_await resolve();
    assert(bool(result.error) == result.addresses.empty());
    if (!result.error || result.error->value() != BootstrapperError::AE_SHUTTING_DOWN) {
        temporary_disabler_update(bool(result.error));
        m_resolved_cache = result.addresses;
    }
    co_return result;
}

void Bootstrapper::remove_resolved(const SocketAddress &addr) {
    m_resolved_cache.erase(std::remove(m_resolved_cache.begin(), m_resolved_cache.end(), addr), m_resolved_cache.end());
}

static std::vector<ResolverPtr> create_resolvers(const Logger &log, const Bootstrapper::Params &p) {
    std::vector<ResolverPtr> resolvers;
    resolvers.reserve(p.bootstrap.size());

    UpstreamOptions opts{};
    opts.outbound_interface = p.outbound_interface;
    for (const std::string &server : p.bootstrap) {
        if (!p.upstream_config.ipv6_available && SocketAddress(ag::utils::split_host_port(server).first, 0).is_ipv6()) {
            continue;
        }
        opts.address = server;
        ResolverPtr resolver = std::make_unique<Resolver>(opts, p.upstream_config);
        if (auto err = resolver->init(); !err) {
            resolvers.emplace_back(std::move(resolver));
        } else {
            log_addr(log, warn, p.address_string, "Failed to create resolver '{}':\n{}", server, err->str());
        }
    }

    if (p.bootstrap.empty() && !ag::utils::str_to_socket_address(p.address_string).valid()) {
        log_addr(log, warn, p.address_string, "Got empty or invalid list of servers for bootstrapping");
    }

    return resolvers;
}

Bootstrapper::Bootstrapper(const Params &p)
        : m_log(__func__)
        , m_timeout(p.timeout)
        , m_resolvers(create_resolvers(m_log, p)) {
    auto [host, port] = utils::split_host_port(p.address_string);
    m_server_port = std::strtol(std::string(port).c_str(), nullptr, 10);
    if (m_server_port == 0) {
        m_server_port = p.default_port;
    }
    m_server_name = host;
    m_shutdown_guard = std::make_shared<bool>(true);
}

Error<Bootstrapper::BootstrapperError> Bootstrapper::init() {
    if (m_resolvers.empty() && !SocketAddress(m_server_name, m_server_port).valid()) {
        return make_error(BootstrapperError::AE_NO_VALID_RESOLVERS);
    }

    return {};
}

std::string Bootstrapper::address() const {
    return AG_FMT("{}:{}", m_server_name, m_server_port);
}

} // namespace ag::dns
