#pragma once

#include <stdint.h>
#include <stdlib.h>

#include "lwipopts.h" // Include before LWIP headers

#include <khash.h>
#include <lwip/prot/tcp.h>
#include <uv.h>

#include "common/logger.h"
#include "tcp_connection.h"
#include "tcpip/tcpip.h"

namespace ag {

typedef struct TcpCtx {
    struct tcp_pcb *tun_pcb;      /**< TUN TCP control block */
    ConnectionTables connections; /**< List of connections */
    ag::Logger log{"TCPIP.TCPMNGR"};
} TcpCtx;

/**
 * Initializes TCP connection manager
 *
 * @param p_params TCP/IP stack configuration parameters
 *
 * @return     true  if one was initialized successfully
 *             false otherwise
 */
bool tcp_cm_init(TcpipCtx *ctx);

/**
 * Closes TCP connection manager
 *
 * @param ctx initialized earlier TCP context instance
 */
void tcp_cm_close(TcpipCtx *ctx);

/**
 * Handles action which should be applied to connection
 *
 * @param ctx context of connection returned by \a tcpip_open
 * @param connection connection descriptor
 * @param action action id (@see tcpip_action_t)
 */
void tcp_cm_complete_connect_request(TcpipCtx *ctx, TcpConnDescriptor *connection, TcpipAction action);

/**
 * Sends data to TCP/IP stack
 *
 * @param conn_descriptor connection descriptor
 * @param data received data
 * @param length size of received data
 */
int tcp_cm_send_data(TcpConnDescriptor *conn_descriptor, const uint8_t *data, size_t length);

/**
 * Cleans up resources after running loop has been stopped
 *
 * @param ctx initialized earlier TCP context instance
 */
void tcp_cm_clean_up(TcpipCtx *ctx);

/**
 * Notify user that some data was sent
 * @param conn_descriptor connection descriptor
 * @param length bytes sent
 */
void tcp_cm_data_sent_notify(TcpConnDescriptor *conn_descriptor, size_t length);

/**
 * Removes descriptor from the list and frees allocated memory for it
 *
 * @param id connection id
 * @param gracefull if true, connection will be closed gracefully
 */
void tcp_cm_close_descriptor(TcpipCtx *ctx, uint64_t id, bool graceful);

/**
 * Handles received data from TCP/IP stack
 *
 * @param descriptor connection descriptor
 * @param data_len size of received data
 * @param data received data
 *
 * @return     0 if success, -1 otherwise
 */
int tcp_cm_receive(TcpConnDescriptor *descriptor, size_t data_len, const uv_buf_t *data);

/**
 * Creates and initializes new TCP connection descriptor
 *
 * @param ctx initialized earlier TCP/IP context instance
 * @param buffer buffer with received packet
 * @param src_addr source ip address
 * @param source_port source port number
 * @param dst_addr destination ip address
 * @param destination_port destination port number
 *
 * @return     successfully created descriptor, or
 *             NULL if something went wrong
 */
TcpConnDescriptor *tcp_cm_create_descriptor(TcpipCtx *ctx, struct pbuf *buffer, const ip_addr_t *src_addr,
        u16_t source_port, const ip_addr_t *dst_addr, u16_t destination_port);

/**
 * Performs a request for next higher layer for new TCP connection
 *
 * @param ctx initialized earlier TCP/IP context instance
 * @param descriptor TCP connection descriptor
 */
void tcp_cm_request_connection(TcpipCtx *ctx, TcpConnDescriptor *descriptor);

/**
 * Notifies TCP connection manager of timer tick event
 *
 * @param ctx initialized earlier TCP/IP context instance
 */
void tcp_cm_timer_tick(TcpipCtx *ctx);

/**
 * Notifies TCP connection manager of accept event on connection
 *
 * @param descriptor TCP connection descriptor
 * @param newpcb TCP connection control block
 *
 * @return     true    if accepted successfully
 *             false   otherwise
 */
bool tcp_cm_accept(TcpConnDescriptor *descriptor, struct tcp_pcb *newpcb);

/**
 * Notify connection that some data raised with `TCPIP_EVENT_READ` callback was
 * sent to remote host
 *
 * @param descriptor TCP connection descriptor
 * @param n number of sent bytes
 */
void tcp_cm_sent_to_remote(TcpConnDescriptor *descriptor, size_t n);

/**
 * Get flow control info for connection
 * @param conn connection descriptor
 */
TcpFlowCtrlInfo tcp_cm_flow_ctrl_info(const TcpConnDescriptor *connection);

} // namespace ag
