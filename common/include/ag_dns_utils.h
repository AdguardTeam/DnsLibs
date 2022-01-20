#pragma once

#include "common/net_utils.h"

namespace ag {

/** Additional info about the DNS message */
struct dns_message_info {
    /** Transport protocol over which the message was received */
    utils::TransportProtocol proto;
    /** Socket address of the peer from which the message was received */
    SocketAddress peername;
};

} // namespace ag
