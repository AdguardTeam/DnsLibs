#pragma once


#include <vector>
#include <string_view>
#include <chrono>

#include "common/logger.h"
#include "common/defs.h"
#include "common/utils.h"
#include "common/socket_address.h"

#include <upstream.h>


namespace ag {


class resolver {
public:
    static constexpr std::chrono::milliseconds MIN_TIMEOUT{ 50 };

    struct result {
        std::vector<SocketAddress> addresses; // List of resolved addresses (empty if failed)
        ErrString error; // non-nullopt in case of something went wrong
    };

    /**
     * Creates resolver for plain DNS address
     * @param options Plain DNS upstream options
     * @param upstream_config Upstream factory configuration for resolving upstreams creation
     */
    resolver(upstream_options options, const upstream_factory_config &upstream_config);

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
    result resolve(std::string_view host, int port, std::chrono::milliseconds timeout) const;
private:
    /** Logger */
    Logger log;
    /** Upstream factory */
    ag::upstream_factory upstream_factory;
    /** Upstream options */
    ag::upstream_options upstream_options;
};


} // namespace ag
