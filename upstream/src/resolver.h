#pragma once


#include <vector>
#include <string_view>
#include <chrono>

#include <ag_logger.h>
#include <ag_defs.h>
#include <ag_utils.h>
#include <ag_socket_address.h>

#include <upstream.h>


namespace ag {


class resolver {
public:
    static constexpr std::chrono::milliseconds MIN_TIMEOUT{ 50 };

    struct result {
        std::vector<socket_address> addresses; // List of resolved addresses (empty if failed)
        err_string error; // non-nullopt in case of something went wrong
    };

    /**
     * Creates resolver for plain DNS address
     * @param resolver_address Plain DNS address
     * @param upstream_config Upstream factory configuration for resolving upstreams creation
     */
    resolver(std::string_view resolver_address, const upstream_factory_config &upstream_config);

    /**
     * Initialize resolver
     * @return non-nullopt if something went wrong
     */
    err_string init();

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
    logger log;
    /** Resolving DNS server address */
    std::string resolver_address;
    /** Upstream factory */
    ag::upstream_factory upstream_factory;
};


} // namespace ag
