#include "outbound_proxy.h"
#include <atomic>


using namespace ag;


static std::atomic_size_t next_id = { 0 };
static std::atomic_uint32_t next_connection_id = { 0 };


outbound_proxy::outbound_proxy(const std::string &logger_name,
        const outbound_proxy_settings *settings, struct parameters parameters)
    : log(create_logger(logger_name))
    , id(next_id.fetch_add(1, std::memory_order::memory_order_relaxed))
    , settings(settings)
    , parameters(parameters)
{}

outbound_proxy::connect_result outbound_proxy::connect(connect_parameters p) {
    uint32_t conn_id = get_next_connection_id();

    if (auto e = this->connect_to_proxy(conn_id, p); e.has_value()) {
        return std::move(e.value());
    }

    return conn_id;
}

uint32_t outbound_proxy::get_next_connection_id() {
    return next_connection_id.fetch_add(1, std::memory_order_relaxed);
}
