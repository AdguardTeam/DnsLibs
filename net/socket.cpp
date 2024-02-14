#include "dns/net/socket.h"
#include <atomic>

namespace ag::dns {

static std::atomic_size_t next_id = {0};

Socket::Socket(const std::string &logger_name, SocketFactory::SocketParameters parameters, PrepareFdCallback prepare_fd)
        : m_log(logger_name)
        , m_id(next_id.fetch_add(1, std::memory_order_relaxed))
        , m_parameters(std::move(parameters))
        , m_prepare_fd(prepare_fd) {
}

utils::TransportProtocol Socket::get_protocol() const {
    return m_parameters.proto;
}

std::optional<std::string> Socket::get_alpn() const {
    return std::nullopt;
}

SocketAddress Socket::get_peer() const {
    std::optional<evutil_socket_t> fd = this->get_fd();
    if (!fd.has_value()) {
        return {};
    }

    return utils::get_peer_address(fd.value()).value_or(SocketAddress{});
}

} // namespace ag::dns
