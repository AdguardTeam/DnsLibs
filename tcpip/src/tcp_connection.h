#pragma once

#include <lwip/pbuf.h>
#include <lwip/tcp.h>

#include "tcpip_connection.h"

namespace ag {

/**
 * Enumeration of states of TCP connection
 */
typedef enum {
    TCP_CONN_STATE_IDLE,
    TCP_CONN_STATE_REQUESTED,
    TCP_CONN_STATE_CONFIRMED,
    TCP_CONN_STATE_HAVE_RESULT,
    TCP_CONN_STATE_REJECTED,
    TCP_CONN_STATE_DROP,
    TCP_CONN_STATE_UNREACHABLE,
    TCP_CONN_STATE_ACCEPTED,
    TCP_CONN_STATE_CLOSING_BY_SERVER,
    TCP_CONN_STATE_CLOSING_BY_CLIENT
} TcpConnState;

/**
 * This struct is used to store the essential parameters of TCP connection
 */
typedef struct {
    TcpipConnection common;
    TcpConnState state;  /**< Connection state */
    struct pbuf *buffer; /**< Raised data buffer */
    struct tcp_pcb *pcb; /**< TCP control block */
} TcpConnDescriptor;

} // namespace ag
