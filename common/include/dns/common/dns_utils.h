#pragma once

#include "common/net_utils.h"

namespace ag::dns {

/** Additional info about the DNS message */
struct DnsMessageInfo {
    /** Transport protocol over which the message was received */
    utils::TransportProtocol proto;
    /** Socket address of the peer from which the message was received */
    SocketAddress peername;
};

namespace dns_utils {

// TODO: This is for backward compatibility: Do not merge this code into 2.1 branch
[[maybe_unused]] static std::tuple<std::string_view, std::string_view, std::optional<std::string>>
split_host_port_with_err(std::string_view host_port, bool require_ipv6_addr_in_square_brackets = false,
                         bool require_non_empty_port = false) {
    auto res = ag::utils::split_host_port(host_port, require_ipv6_addr_in_square_brackets, require_non_empty_port);
    if (res.has_error()) {
        return {host_port, {}, res.error()->str()};
    }
    return {res->first, res->second, {}};
}

[[maybe_unused]]
static std::pair<std::string_view, std::string_view> split_host_port(std::string_view host_port) {
    auto [host, port, err] = split_host_port_with_err(host_port);
    return {host, port};
}

} // namespace utils

} // namespace ag::dns
