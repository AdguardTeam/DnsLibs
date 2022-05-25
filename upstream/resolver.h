#pragma once


#include <vector>
#include <string_view>
#include <chrono>

#include "common/logger.h"
#include "common/defs.h"
#include "common/utils.h"
#include "common/socket_address.h"

#include "upstream/upstream.h"


namespace ag {


class Resolver {
public:
    static constexpr Millis MIN_TIMEOUT{ 50 };

    struct Result {
        std::vector<SocketAddress> addresses; // List of resolved addresses (empty if failed)
        ErrString error; // non-nullopt in case of something went wrong
    };

    /**
     * Creates resolver for plain DNS address
     * @param options Plain DNS upstream options
     * @param upstream_config Upstream factory configuration for resolving upstreams creation
     */
    Resolver(UpstreamOptions options, const UpstreamFactoryConfig &upstream_config);

    /**
     * Initialize resolver
     * @return non-nullopt if something went wrong
     */
    ErrString init();

    /**
     * Resolves host to list of socket addresses with given port attached
     * @param host Destination host to resolve
     * @param port Destination port to place into socket addresses
     * @param timeout Resolve timeout
     * @return See `resolver::result` structure
     */
    Result resolve(std::string_view host, int port, Millis timeout) const;
private:
    /** Logger */
    Logger m_log;
    /** Upstream factory */
    ag::UpstreamFactory m_upstream_factory;
    /** Upstream options */
    ag::UpstreamOptions m_upstream_options;
};


} // namespace ag
