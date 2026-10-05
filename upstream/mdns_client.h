#pragma once

#include <functional>
#include <memory>
#include <string_view>
#include <vector>

#include "common/coro.h"
#include "common/defs.h"
#include "common/socket_address.h"
#include "dns/common/dns_defs.h"
#include "dns/common/event_loop.h"
#include "dns/net/socket.h"

namespace ag::dns {

/**
 * A Multicast DNS (RFC 6762) client, used to resolve names in the `.local` domain.
 *
 * One-shot queries are sent with the unicast-response (QU) bit set, so responders reply
 * directly to the client's ephemeral source port. In addition, the client joins the mDNS
 * multicast group on port 5353 and keeps listener sockets open while requests are pending,
 * because a responder may multicast its answer instead of unicasting it. The returned reply
 * is a regular DNS packet, so the proxy response cache handles the resolved records (with
 * their original TTLs) as usual.
 *
 * IPv4 (224.0.0.251) is used by default; IPv6 (ff02::fb, per link-local interface) is opt-in
 * via `Config::enable_ipv6`. mDNS is transport-agnostic, so AAAA questions are answered over
 * the IPv4 group on dual-stack networks.
 *
 * Platform integration (Android): `Config::set_multicast_enabled` tells the platform when to
 * hold a `WifiManager.MulticastLock`, and `Config::configure_socket` applies an explicit
 * network binding when the upstream is configured with an interface.
 */
class MdnsClient {
public:
    static constexpr uint16_t MDNS_PORT = 5353;

    /**
     * Default overall deadline for a single resolution. Kept short because a responder either
     * answers within milliseconds or does not answer at all (mDNS negative answers are NSEC
     * records, which are recognized; silence means the name could not be resolved).
     */
    static constexpr Millis DEFAULT_TIMEOUT{2000};

    /** How long multicast listener sockets are kept after the last pending request completes. */
    static constexpr Millis DEFAULT_IDLE_TIMEOUT{5000};

    struct Config {
        /** Event loop that drives the queries. Must be set. */
        EventLoop *loop = nullptr;
        /**
         * Socket factory used to apply route-loop protection and interface binding to the
         * client's sockets, the same way it is applied to other upstream sockets. Optional.
         */
        SocketFactory *socket_factory = nullptr;
        /** Network interface to send queries through. Optional. */
        IfIdVariant outbound_interface;
        /** Overall deadline for a single resolution. */
        Millis timeout = DEFAULT_TIMEOUT;
        /** How long listener sockets (and the platform multicast lock) are kept after the last
         *  pending request completes. */
        Millis idle_timeout = DEFAULT_IDLE_TIMEOUT;
        /**
         * Explicit unicast query destinations (used by tests). When empty, queries are sent to
         * the mDNS multicast groups on `multicast_port` and multicast listeners are opened.
         */
        std::vector<SocketAddress> servers;
        /** mDNS port. 5353 by default; overridable for tests and non-standard setups. */
        uint16_t multicast_port = MDNS_PORT;
        bool enable_ipv4 = true;
        /**
         * IPv6 transport is opt-in. mDNS is transport-agnostic, so AAAA questions are answered
         * over the IPv4 group on dual-stack networks; enable this only for IPv6-only networks
         * (it adds a query socket and group joins per link-local interface).
         */
        bool enable_ipv6 = false;
        /**
         * Platform-specific socket setup, called for every created socket before it is bound.
         * On Android this binds the socket to the network handle of the `system://<interface>`
         * upstream, when one is configured. Returning an error aborts the request.
         */
        std::function<Error<DnsError>(evutil_socket_t)> configure_socket;
        /**
         * Called when the client starts/stops using multicast: Android uses it to hold a
         * `WifiManager.MulticastLock` while the listener sockets are open.
         */
        std::function<void(bool)> set_multicast_enabled;
    };

    static std::unique_ptr<MdnsClient> create(Config config);

    ~MdnsClient();

    MdnsClient(const MdnsClient &) = delete;
    MdnsClient &operator=(const MdnsClient &) = delete;
    MdnsClient(MdnsClient &&) = delete;
    MdnsClient &operator=(MdnsClient &&) = delete;

    /**
     * Returns true if `name` belongs to the mDNS `.local` domain (case-insensitive, with or
     * without the trailing dot).
     */
    [[nodiscard]] static bool is_local_name(std::string_view name);

    /**
     * Sends a one-shot mDNS query for the first question of `request` and returns the reply.
     *
     * The reply preserves the request ID and question section, contains the collected answer
     * and additional records with their original TTLs, or is an NXDOMAIN response with a SOA
     * record when no responder answered before the deadline.
     */
    coro::Task<Result<ldns_pkt_ptr, DnsError>> exchange(const ldns_pkt *request);

private:
    class Impl;

    explicit MdnsClient(Config config);

    std::unique_ptr<Impl> m_pimpl;
};

} // namespace ag::dns
