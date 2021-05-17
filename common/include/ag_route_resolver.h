#pragma once

#include <memory>
#include <optional>
#include <ag_socket_address.h>

namespace ag {

class route_resolver;
using route_resolver_ptr = std::unique_ptr<route_resolver>;

/**
 * When we are working as a network extension on an Apple platform,
 * and we want to communicate with a destination host for which a route
 * exists, created by some other network extension, through that network
 * extension's interface, the OS will refuse to route our packet
 * through that tunnel. To circumvent this, we can explicitly bind
 * our socket to the specific interface. This class makes that
 * possible by parsing the system routing table and extracting
 * a mapping from a host/netmask to an interface index.
 * On other platforms this class does nothing.
 */
class route_resolver {
public:
    /**
     * Return an interface that should be used to connect to `address`,
     * (see setsockopt(), IP_BOUND_IF, IPV6_BOUND_IF), or std::nullopt
     * if no interface could be found for the destination.
     * Thread-safe.
     * On non-Apple always return std::nullopt.
     */
    virtual std::optional<uint32_t> resolve(const ag::socket_address &address) = 0;

    /**
     * Flush the routing table cache.
     */
    virtual void flush_cache() = 0;

    virtual ~route_resolver() = default;

    /** Create a new route resolver */
    static route_resolver_ptr create();
};

} // namespace ag
