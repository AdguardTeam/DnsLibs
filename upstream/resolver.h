#pragma once


#include <vector>
#include <string_view>
#include <chrono>

#include "common/logger.h"
#include "common/defs.h"
#include "common/utils.h"
#include "common/socket_address.h"

#include "dns/upstream/upstream.h"


namespace ag {
namespace dns {

class Resolver {
public:
    static constexpr Millis MIN_TIMEOUT{50};

    enum ResolverError {
        AE_INVALID_ADDRESS,
        AE_UPSTREAM_INIT_FAILED,
        AE_EXCHANGE_FAILED,
        AE_EMPTY_ADDRS,
        AE_SHUTTING_DOWN,
    };

    using Result = ag::Result<std::vector<SocketAddress>, ResolverError>;

    /**
     * Creates resolver for plain DNS address
     * @param options Plain DNS upstream options
     * @param upstream_config Upstream factory configuration for resolving upstreams creation
     */
    Resolver(UpstreamOptions options, const UpstreamFactoryConfig &upstream_config);

    ~Resolver();

    /**
     * Initialize resolver
     * @return non-nullopt if something went wrong
     */
    Error<ResolverError> init();

    /**
     * Resolves host to list of socket addresses with given port attached
     * @param host Destination host to resolve
     * @param port Destination port to place into socket addresses
     * @param timeout Resolve timeout
     * @return See `resolver::result` structure
     */
    [[nodiscard]] coro::Task <Result> resolve(std::string_view host, int port, Millis timeout) const;

private:
    /** Logger */
    Logger m_log;
    /** Upstream factory */
    UpstreamFactory m_upstream_factory;
    /** Upstream options */
    UpstreamOptions m_upstream_options;
    /** Shutdown guard */
    std::shared_ptr<bool> m_shutdown_guard;
};

} // namespace dns

template<>
struct ErrorCodeToString<dns::Resolver::ResolverError> {
    std::string operator()(dns::Resolver::ResolverError e) {
        switch (e) {
        case decltype(e)::AE_INVALID_ADDRESS: return "Invalid resolver address";
        case decltype(e)::AE_UPSTREAM_INIT_FAILED: return "Failed to create upstream";
        case decltype(e)::AE_EXCHANGE_FAILED: return "Failed to talk to upstream";
        case decltype(e)::AE_EMPTY_ADDRS: return "No addresses received for host";
        case decltype(e)::AE_SHUTTING_DOWN: return "Shutting down";
        default: return "Unknown error";
        }
    }
};

} // namespace ag
