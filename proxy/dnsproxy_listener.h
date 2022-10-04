#pragma once

#include "common/defs.h"
#include "common/error.h"
#include "dns/proxy/dnsproxy.h"

namespace ag::dns {

class DnsProxyListener;
using ListenerPtr = std::unique_ptr<DnsProxyListener>;

class DnsProxyListener {
public:
    virtual ~DnsProxyListener() = default;

    using CreateResult = Result<ListenerPtr, DnsProxyInitError>;

    /**
     * Create a listener and start listening
     * @param settings Listener settings
     * @param proxy    Dnsproxy to use for handling requests
     * @param loop     Event loop
     * @return a listener pointer or an error string
     */
    static CreateResult create_and_listen(const ListenerSettings &settings, DnsProxy *proxy, EventLoop *loop);

    /**
     * @brief Get the address is being listened for queries
     */
    [[nodiscard]] virtual std::pair<utils::TransportProtocol, SocketAddress> get_listen_address() const = 0;
};

} // namespace ag::dns
