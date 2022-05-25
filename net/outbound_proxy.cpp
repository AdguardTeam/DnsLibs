#include "outbound_proxy.h"
#include <atomic>

using namespace ag;

static std::atomic_size_t next_id = {0};
static std::atomic_uint32_t next_connection_id = {0};

OutboundProxy::OutboundProxy(
        const std::string &logger_name, const OutboundProxySettings *settings, Parameters parameters)
        : m_log(logger_name)
        , m_id(next_id.fetch_add(1, std::memory_order::memory_order_relaxed))
        , m_settings(settings)
        , m_parameters(parameters) {
}

OutboundProxy::ConnectResult OutboundProxy::connect(ConnectParameters p) {
    uint32_t conn_id = get_next_connection_id();

    if (auto e = this->connect_to_proxy(conn_id, p); e.has_value()) {
        return std::move(e.value());
    }

    return conn_id;
}

uint32_t OutboundProxy::get_next_connection_id() {
    return next_connection_id.fetch_add(1, std::memory_order_relaxed);
}
