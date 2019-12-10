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
        bool ipv6_avail; // true if ipv6 is available
        const std::vector<std::string> &bootstrap; // list of the resolving servers
        std::chrono::milliseconds timeout; // resolve timeout
        const upstream_factory::config &upstream_config; // configuration of the upstream factory which creates resolving upstream
    };

    bootstrapper(const params &p);

    struct resolve_result {
        std::vector<socket_address> addresses; // not empty resolved addresses list in case of success
        std::string server_name; // resolved host name
        std::chrono::microseconds time_elapsed; // time took to resolve
        err_string error; // non-nullopt if something went wrong
    };

    /**
     * Get resolved address from bootstrapper
     */
    resolve_result get();
    /**
     * Get all the resolved addresses from bootstrapper
     */
    resolve_result get_all();
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
    /** Round robin number for choosing upstream */
    std::atomic_int m_round_robin_num;
    /** List of resolvers to use */
    std::vector<resolver_ptr> m_resolvers;
    /** Is IPv6 available in system */
    bool m_ipv6_avail;
};

using bootstrapper_ptr = std::unique_ptr<bootstrapper>;

} // namespace ag
