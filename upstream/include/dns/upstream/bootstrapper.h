#pragma once

#include <memory>
#include <string>
#include <vector>

#include "common/logger.h"
#include "common/socket_address.h"
#include "dns/upstream/upstream.h"

namespace ag {
namespace dns {

class Resolver;
using ResolverPtr = std::unique_ptr<Resolver>;

class Bootstrapper {
public:
    struct Params {
        std::string_view address_string; // host to be resolved
        int default_port; // default to be used if not specified in `address_string`
        const std::vector<std::string> &bootstrap; // list of the resolving servers
        Millis timeout; // resolve timeout
        const UpstreamFactoryConfig &upstream_config; // configuration of the upstream factory which creates resolving upstream
        IfIdVariant outbound_interface; // interface to bind sockets to
    };

    explicit Bootstrapper(const Params &p);
    ~Bootstrapper();
    Bootstrapper(Bootstrapper &&);
    Bootstrapper &operator=(Bootstrapper &&);

    enum BootstrapperError {
        AE_NO_VALID_RESOLVERS,
        AE_EMPTY_LIST,
        AE_RESOLVE_FAILED,
        AE_TEMPORARY_DISABLED,
        AE_SHUTTING_DOWN,
    };

    /**
     * Initialize bootstrapper
     * @return non-nullopt if something went wrong
     */
    Error<BootstrapperError> init();

    struct ResolveResult {
        std::vector<SocketAddress> addresses; // not empty resolved addresses list in case of success
        std::string server_name; // resolved host name
        Micros time_elapsed; // time took to resolve
        Error<BootstrapperError> error; // non-nullopt if something went wrong
    };

    /**
     * Get resolved addresses from bootstrapper
     */
    coro::Task<ResolveResult> get();

    /**
     * Remove resolved address from the cache
     * @param addr address to remove
     */
    void remove_resolved(const SocketAddress &addr);

    /**
     * Get address to resolve from bootstrapper
     */
    [[nodiscard]] std::string address() const;

    // Non-copyable
    Bootstrapper(const Bootstrapper &) = delete;
    Bootstrapper &operator=(const Bootstrapper &) = delete;

private:
    /**
     * Check if bootstrapper should be temporary disabled
     */
    ErrString temporary_disabler_check();

    /**
     * Update information for temporary disabling bootstrapper
     */
    void temporary_disabler_update(bool fail);

    coro::Task<ResolveResult> resolve();

    /** Logger */
    Logger m_log;
    /** Server name to resolve */
    std::string m_server_name;
    /** Server port */
    int m_server_port;
    /** Resolve timeout */
    Millis m_timeout;
    /** Resolved addresses cache */
    std::vector<SocketAddress> m_resolved_cache;
    /** Times of first and last remove fails */
    std::pair<int64_t, int64_t> m_resolve_fail_times_ms;
    /** List of resolvers to use */
    std::vector<ResolverPtr> m_resolvers;
    /** Shutdown guard */
    std::shared_ptr<bool> m_shutdown_guard;
};

using BootstrapperPtr = std::unique_ptr<Bootstrapper>;

} // namespace dns

template<>
struct ErrorCodeToString<dns::Bootstrapper::BootstrapperError> {
    std::string operator()(dns::Bootstrapper::BootstrapperError e) {
        switch (e) {
        case decltype(e)::AE_NO_VALID_RESOLVERS: return "Failed to create any resolver";
        case decltype(e)::AE_EMPTY_LIST: return "Empty bootstrap list";
        case decltype(e)::AE_RESOLVE_FAILED: return "Failed to resolve host";
        case decltype(e)::AE_TEMPORARY_DISABLED: return "Bootstrapping this server is temporary disabled due to many failures";
        case decltype(e)::AE_SHUTTING_DOWN: return "Shutting down";
        default: return "Unknown error";
        }
    }
};

} // namespace ag
