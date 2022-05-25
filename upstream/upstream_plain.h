#pragma once

#include <utility>
#include "upstream/upstream.h"
#include <event2/event.h>
#include <ldns/net.h>
#include "dns_framed.h"

namespace ag {

class PlainUpstream;

/**
 * Pool of TCP connections
 */
class TcpPool : public DnsFramedPool {
public:
    /**
     * Create pool of TCP connections
     * @param loop Event loop
     * @param address Destination socket address
     * @upstream Parent upstream
     */
    TcpPool(EventLoopPtr loop, const SocketAddress &address, PlainUpstream *upstream);

    GetResult get() override;

    const SocketAddress &address() const;

private:
    /** Destination socket address */
    SocketAddress m_address;

    GetResult create();
};

/**
 * Plain DNS upstream
 */
class PlainUpstream : public Upstream {
public:
    static constexpr std::string_view TCP_SCHEME = "tcp://";
    static constexpr int DEFAULT_PORT = 53;

    /**
     * Create plain DNS upstream
     * @param opts Upstream settings
     */
    PlainUpstream(const UpstreamOptions &opts, const UpstreamFactoryConfig &config);

    ~PlainUpstream() override = default;

private:
    ErrString init() override;
    ExchangeResult exchange(ldns_pkt *request_pkt, const DnsMessageInfo *info) override;

    Logger m_log;

    friend class TcpPool;

    /** Prefer TCP */
    bool m_prefer_tcp;
    /** TCP connection pool */
    TcpPool m_pool;
};

} // namespace ag
