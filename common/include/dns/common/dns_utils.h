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

} // namespace ag::dns
