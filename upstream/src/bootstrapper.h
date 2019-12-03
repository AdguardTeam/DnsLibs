#pragma once

#include <string>
#include <upstream.h>
#include "upstream_plain.h"

namespace ag {

class resolver;
using resolver_ptr = std::shared_ptr<resolver>;

class bootstrapper {
public:
    bootstrapper(std::string_view address_string, int default_port, bool ipv6_avail, const std::vector<std::string> &bootstrap);
    struct ret {
        std::optional<ag::socket_address> address;
        std::string server_name;
        std::chrono::microseconds time_elapsed;
        ag::err_string error;
    };
    /**
     * Get resolved address from bootstrapper
     */
    ret get();
    /**
     * Get address to resolve from bootstrapper
     */
    std::string address();

    // Non-copyable
    bootstrapper(const bootstrapper &) = delete;
    bootstrapper &operator=(const bootstrapper &) = delete;
private:
    /** Server name to resolve */
    std::string m_server_name;
    /** Server port */
    int m_server_port;
    /** List of resolvers to use */
    std::vector<resolver_ptr> m_resolvers;
    /** Resolved addresses cache */
    std::vector<ag::socket_address> m_resolved_cache;
    /** Resolved addresses cache mutex */
    std::mutex m_resolved_cache_mutex;
    /** Round robin number for choosing upstream */
    std::atomic_int m_round_robin_num;
    /** Is IPv6 available in system */
    bool m_ipv6_avail;
};

class resolver {
public:
    /**
     * Creates resolver for plain DNS address
     * @param resolver_address Plain DNS address
     */
    explicit resolver(std::string_view resolver_address);
    /**
     * Resolves host to list of socket addresses with given port attached
     * @param host Destination host to resolve
     * @param port Destination port to place into socket addresses
     * @param timeout Resolve timeout
     * @param ipv6_avail If false, DNS servers will not be queried for AAAA
     * @return List of socket addresses
     */
    std::vector<socket_address> resolve(std::string_view host, int port, std::chrono::milliseconds timeout, bool ipv6_avail);
private:
    /** Plain DNS address (@see ag::plain_dns::plain_dns) */
    std::string m_resolver_address;
};

using bootstrapper_ptr = std::shared_ptr<bootstrapper>;

} // namespace ag
