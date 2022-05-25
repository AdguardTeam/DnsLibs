#pragma once

#include "common/defs.h"
#include "proxy/dnsproxy.h"

namespace ag {

class DnsProxyListener;
using ListenerPtr = std::unique_ptr<DnsProxyListener>;

class DnsProxyListener {
public:
    virtual ~DnsProxyListener() = default;

    using CreateResult = std::pair<ListenerPtr, ErrString>;

    /**
     * Create a listener and start listening
     * @param settings the listener settings
     * @param proxy    the dnsproxy to use for handling requests
     * @return a listener pointer or an error string
     */
    static CreateResult create_and_listen(const ListenerSettings &settings, DnsProxy *proxy);

    /**
     * Request this listener to shutdown
     */
    virtual void shutdown() = 0;

    /**
     * Block until the listener shuts down
     */
    virtual void await_shutdown() = 0;

    /**
     * @brief Get the address is being listened for queries
     */
    [[nodiscard]] virtual std::pair<utils::TransportProtocol, SocketAddress> get_listen_address() const = 0;
};

} // namespace ag
