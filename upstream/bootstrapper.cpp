#include <algorithm>
#include <cassert>

#if defined _WIN32 && !defined __clang__
#pragma optimize( "", off )
#endif
#include "common/parallel.h"
#if defined _WIN32 && !defined __clang__
#pragma optimize( "", on )
#endif
#include "common/utils.h"
#include "dns/dnsstamp/dns_stamp.h"
#include "dns/upstream/bootstrapper.h"
#include "resolver.h"

#define log_addr(l_, lvl_, addr_, fmt_, ...) lvl_##log(l_, "[{}] " fmt_, addr_, ##__VA_ARGS__)

namespace ag::dns {

using std::chrono::duration_cast;

// For each resolver a half of time out is given for a try. If one fails, it's moved to the end
// of the list to give it a chance in the future.
//
// Note: in case of success MUST always return vector of addresses in address field of result
coro::Task<void> Bootstrapper::do_resolve() {
    HashSet<SocketAddress> addrs;
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
        co_return;
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

    std::vector<SocketAddress> addresses(std::move_iterator(addrs.begin()), std::move_iterator(addrs.end()));
    complete_resolve({std::move(addresses), m_server_name, {},
            error ? error->value() == Resolver::ResolverError::AE_SHUTTING_DOWN
                            ? make_error(BootstrapperError::AE_SHUTTING_DOWN, error)
                            : make_error(BootstrapperError::AE_RESOLVE_FAILED, error)
                  : nullptr});
}

std::optional<Bootstrapper::ResolveResult> Bootstrapper::try_get_ready_result() {
    if (SocketAddress addr(m_server_name, m_server_port); addr.valid()) {
        return ResolveResult{{addr}, m_server_name, Millis(0), {}};
    }
    if (!m_resolved_cache.empty()) {
        return ResolveResult{m_resolved_cache, m_server_name, Millis(0), {}};
    }
    if (m_resolvers.empty()) {
        return ResolveResult{{}, m_server_name, Millis(0), make_error(BootstrapperError::AE_EMPTY_LIST)};
    }
    return std::nullopt;
}

void Bootstrapper::request_resolve(std::function<void(ResolveResult)> &&handler) {
    bool in_progress = !m_request_handlers.empty();
    m_request_handlers.emplace_back(std::move(handler));
    if (!in_progress || SteadyClock::now() - m_last_resolve_time > Millis(500)) {
        m_last_resolve_time = SteadyClock::now();
        coro::run_detached(do_resolve());
    }
}

void Bootstrapper::complete_resolve(ResolveResult result) {
    if (!result.error) {
        m_resolved_cache = result.addresses;
    }
    std::list<RequestHandler> request_handlers;
    request_handlers.swap(m_request_handlers);
    for (auto it = request_handlers.begin(); it != request_handlers.end(); it++) {
        result.time_elapsed = it->timer.elapsed<Millis>();
        it->handler(result);
    }
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
        auto split_result = ag::utils::split_host_port(server);
        if (!p.upstream_config.ipv6_available
                && !split_result.has_error()
                && SocketAddress(split_result.value().first, 0).is_ipv6()) {
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
    auto split_result = utils::split_host_port(p.address_string);
    if (!split_result.has_error()) {
        auto [host, port] = split_result.value();
        m_server_port = utils::to_integer<uint16_t>(port).value_or(p.default_port);
        m_server_name = host;
    }
    m_shutdown_guard = std::make_shared<bool>(true);
}

Bootstrapper::~Bootstrapper() {
    complete_resolve(Bootstrapper::ResolveResult{
            .server_name = m_server_name,
            .error = make_error(BootstrapperError::AE_SHUTTING_DOWN)
    });
}
Bootstrapper::Bootstrapper(Bootstrapper &&) = default;
Bootstrapper &Bootstrapper::operator=(Bootstrapper &&) = default;

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
