#pragma once

#include <memory>
#include <optional>

#include "common/net_utils.h"

namespace ag::dns {

/** Additional info about the DNS message */
struct DnsMessageInfo {
    /** The subset of \ref DnsProxySettings available for overriding on a specific message */
    struct ProxySettingsOverrides {
        /** \ref DnsProxySettings.block_ech, has no effect if `nullopt` */
        std::optional<bool> block_ech;
    };

    /** Transport protocol over which the message was received */
    utils::TransportProtocol proto;
    /** Socket address of the peer from which the message was received */
    SocketAddress peername;
    /** Overridden settings */
    ProxySettingsOverrides settings_overrides;
};

/** Return `nullptr` if `opt.has_value() == false`, or `std::addressof(opt.value())` if `opt.has_value() == true`. */
template <typename T>
T *opt_as_ptr(std::optional<T> &opt) {
    if (opt.has_value()) {
        return std::addressof(*opt);
    }
    return nullptr;
}

} // namespace ag::dns
