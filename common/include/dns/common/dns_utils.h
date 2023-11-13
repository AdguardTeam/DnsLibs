#pragma once

#include <memory>
#include <optional>

#include "common/defs.h"
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
    utils::TransportProtocol proto = utils::TP_UDP;
    /** Socket address of the peer from which the message was received */
    SocketAddress peername;
    /** Overridden settings */
    ProxySettingsOverrides settings_overrides;
    /**
     * Indicates whether the caller wishes to filter this message transparently.
     *
     * If `false`, the proxy processes the message in a usual way, and the final response is returned.
     *
     * If `true`, and the message is a query, the proxy won't pass it to the upstream (it may still make an upstream
     * request in order to process CNAME-rewrites, for example), instead, it will return the processed request, which
     * the caller should pass to the upstream, or a generated response, which the caller should pass to the client.
     *
     * If `true`, and this message is a response, the proxy will process the message as if it was received from an
     * upstream, and return the processed response, which the caller should pass to the client.
     *
     * When filtering transparently, the proxy will NOT perform DNS64 synthesis.
     */
    bool transparent = false;
};

/** Return `nullptr` if `opt.has_value() == false`, or `std::addressof(opt.value())` if `opt.has_value() == true`. */
template <typename T>
T *opt_as_ptr(std::optional<T> &opt) {
    if (opt.has_value()) {
        return std::addressof(*opt);
    }
    return nullptr;
}

/** Return `true` if `pkt` is a DNS response, `false` in all other cases. */
inline bool is_response(Uint8View pkt) {
    if (pkt.size() >= 3) {
        // Return the value of the QR bit
        return pkt[2] & 0x80; // NOLINT(*-avoid-magic-numbers)
    }
    return false;
}

} // namespace ag::dns
