#pragma once

#include <ag_net_utils.h>

namespace ag {

/** Additional info about the DNS message */
struct dns_message_info {
    /** Transport protocol over which the message was received */
    utils::transport_protocol proto;
    /** Socket address of the peer from which the message was received */
    SocketAddress peername;
};

} // namespace ag
