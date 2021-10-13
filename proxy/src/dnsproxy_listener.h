#pragma once

#include <ag_defs.h>
#include <dnsproxy.h>

namespace ag {

class dnsproxy_listener;
using listener_ptr = std::unique_ptr<dnsproxy_listener>;

class dnsproxy_listener {
public:
    virtual ~dnsproxy_listener() = default;

    using create_result = std::pair<listener_ptr, err_string>;

    /**
     * Create a listener and start listening
     * @param settings the listener settings
     * @param proxy    the dnsproxy to use for handling requests
     * @return a listener pointer or an error string
     */
    static create_result create_and_listen(const listener_settings &settings, dnsproxy *proxy);

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
    [[nodiscard]] virtual std::pair<utils::transport_protocol, socket_address> get_listen_address() const = 0;
};

} // namespace ag
