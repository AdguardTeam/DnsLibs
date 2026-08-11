#pragma once

#include <memory>

#include "dns/upstream/bootstrapper.h"
#include "dns/upstream/upstream.h"

#include "dns_framed.h"

namespace ag::dns {

/**
 * Intermediate `DnsFramedConnection` subclass for framed-DNS connections (DoT,
 * plain DNS over TCP) that can resolve a hostname upstream address via the
 * upstream's bootstrapper before connecting.
 *
 * The concrete connection subclasses (defined alongside their upstreams) only
 * supply the protocol-specific bits through the hooks below: a stream factory,
 * the parent upstream's bootstrapper, and the fallback address used when there
 * is nothing to bootstrap. Everything else -- resolving the hostname, racing
 * one IPv4 and one IPv6 connect attempt, evicting failed addresses from the
 * bootstrap cache and wiring up the winning stream -- is shared here.
 *
 * The hooks are public because the local connect-attempt machinery inside
 * `co_connect()` calls them; this class is internal to the `upstream` library
 * and is not part of a public API.
 */
class BootstrappedFramedConnection : public DnsFramedConnection {
public:
    using DnsFramedConnection::DnsFramedConnection;

    /**
     * Create a protocol-specific TCP stream for a connect attempt (e.g. a TLS
     * socket for DoT, a plain socket for plain DNS). The target address is
     * supplied separately to `connect()`.
     */
    virtual SocketFactory::SocketPtr make_stream(const std::shared_ptr<Upstream> &upstream) = 0;

    /**
     * The parent upstream's bootstrapper, or nullptr when the upstream address
     * is a numeric IP (no hostname resolution needed).
     */
    virtual Bootstrapper *bootstrapper(const std::shared_ptr<Upstream> &upstream) = 0;

    /**
     * Address used when no bootstrapper is present (the upstream's resolved
     * numeric address, or the bare hostname:port pair for DoT).
     */
    virtual AddressVariant no_bootstrap_address(const std::shared_ptr<Upstream> &upstream) = 0;

    /** Start the TCP connect asynchronously (resolving the hostname first if needed). */
    void connect() override;

    /** On a request failure, drop the used resolved address from the bootstrap cache. */
    void finish_request(uint16_t request_id, Reply &&reply) override;

private:
    coro::Task<void> co_connect();
};

} // namespace ag::dns
