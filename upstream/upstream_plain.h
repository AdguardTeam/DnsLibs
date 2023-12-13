#pragma once

#include <memory>
#include <utility>

#include <event2/event.h>
#include <ldns/net.h>

#include "dns/upstream/upstream.h"

#include "dns_framed.h"

namespace ag::dns {

class PlainUpstream;

/**
 * Plain DNS upstream
 */
class PlainUpstream : public Upstream {
public:
    static constexpr std::string_view TCP_SCHEME = "tcp:";
    static constexpr std::string_view UDP_SCHEME = "udp:";

    /**
     * Create plain DNS upstream
     * @param opts Upstream settings
     */
    PlainUpstream(const UpstreamOptions &opts, const UpstreamFactoryConfig &config);

    ~PlainUpstream() override = default;

private:
    Error<InitError> init() override;
    coro::Task<ExchangeResult> exchange(const ldns_pkt *request_pkt, const DnsMessageInfo *info) override;

    Logger m_log;

    friend class TcpPool;

    /** Prefer TCP */
    bool m_prefer_tcp;
    /** Prefer UDP */
    bool m_prefer_udp;
    /** TCP connection pool */
    ConnectionPoolPtr m_pool;
    /** Socket address */
    SocketAddress m_address;
    /** Use of deleted *this prevention */
    std::shared_ptr<bool> m_shutdown_guard;
};

} // namespace ag::dns
