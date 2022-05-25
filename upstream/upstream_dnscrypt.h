#pragma once

#include <chrono>
#include <memory>
#include "dnsstamp/dns_stamp.h"
#include "upstream/upstream.h"
#include "common/logger.h"

namespace ag {

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
    ErrString init() override;
    ExchangeResult exchange(ldns_pkt *request_pkt, const DnsMessageInfo *info) override;

    struct Impl;
    using ImplPtr = std::unique_ptr<Impl>;

    struct SetupResult {
        Millis rtt;
        ErrString error;
    };

    SetupResult setup_impl();
    ExchangeResult apply_exchange(ldns_pkt &request_pkt, Millis timeout);
    [[nodiscard]] SocketFactory::SocketParameters make_socket_parameters() const;

    Logger m_log;
    ServerStamp m_stamp;
    ImplPtr m_impl;
    std::mutex m_guard;
};

} // namespace ag
