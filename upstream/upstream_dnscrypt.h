#pragma once

#include <chrono>
#include <memory>
#include "dns/dnsstamp/dns_stamp.h"
#include "dns/upstream/upstream.h"
#include "common/logger.h"

namespace ag::dns {

class DnscryptUpstream : public Upstream {
public:
    /**
     * Create DNSCrypt upstream
     * @param stamp Stamp
     * @param opts Upstream settings
     */
    DnscryptUpstream(ServerStamp &&stamp, const UpstreamOptions &opts, const UpstreamFactoryConfig &config);
    DnscryptUpstream(const DnscryptUpstream &) = delete;
    DnscryptUpstream &operator=(const DnscryptUpstream &) = delete;
    ~DnscryptUpstream() override;

private:
    Error<InitError> init() override;
    coro::Task<ExchangeResult> exchange(ldns_pkt *request_pkt, const DnsMessageInfo *info) override;

    struct Impl;
    using ImplPtr = std::unique_ptr<Impl>;

    struct SetupResult {
        Millis rtt;
        Error<DnsError> error;
    };

    coro::Task<SetupResult> setup_impl();
    coro::Task<ExchangeResult> apply_exchange(ldns_pkt &request_pkt, Millis timeout);
    [[nodiscard]] SocketFactory::SocketParameters make_socket_parameters() const;

    Logger m_log;
    ServerStamp m_stamp;
    ImplPtr m_impl;
};

} // namespace ag::dns
