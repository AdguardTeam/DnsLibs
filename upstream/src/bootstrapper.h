#pragma once

#include <string>
#include <vector>
#include <memory>
#include <ag_logger.h>
#include <ag_socket_address.h>
#include <upstream.h>
#include "resolver.h"

namespace ag {

class resolver;
using resolver_ptr = std::unique_ptr<resolver>;

class bootstrapper {
public:
    struct params {
        std::string_view address_string; // host to be resolved
        int default_port; // default to be used if not specified in `address_string`
        const std::vector<std::string> &bootstrap; // list of the resolving servers
        std::chrono::milliseconds timeout; // resolve timeout
        const upstream_factory_config &upstream_config; // configuration of the upstream factory which creates resolving upstream
    };

    explicit bootstrapper(const params &p);

    /**
     * Initialize bootstrapper
     * @return non-nullopt if something went wrong
     */
    err_string init();

    struct resolve_result {
        std::vector<socket_address> addresses; // not empty resolved addresses list in case of success
        std::string server_name; // resolved host name
        std::chrono::microseconds time_elapsed; // time took to resolve
        err_string error; // non-nullopt if something went wrong
    };

    /**
     * Get resolved addresses from bootstrapper
     */
    resolve_result get();

    /**
     * Remove resolved address from the cache
     * @param addr address to remove
     */
    void remove_resolved(const socket_address &addr);

    /**
     * Get address to resolve from bootstrapper
     */
    std::string address() const;

    // Non-copyable
    bootstrapper(const bootstrapper &) = delete;
    bootstrapper &operator=(const bootstrapper &) = delete;
private:
    resolve_result resolve();

    /** Logger */
    logger m_log;
    /** Server name to resolve */
    std::string m_server_name;
    /** Server port */
    int m_server_port;
    /** Resolve timeout */
    std::chrono::milliseconds m_timeout;
    /** Resolved addresses cache */
    std::vector<socket_address> m_resolved_cache;
    /** Resolved addresses cache mutex */
    std::mutex m_resolved_cache_mutex;
    /** List of resolvers to use */
    std::vector<resolver_ptr> m_resolvers;
};

using bootstrapper_ptr = std::unique_ptr<bootstrapper>;

} // namespace ag
