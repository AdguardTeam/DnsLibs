#pragma once

#include <lwip/init.h>
#include <lwip/tcp.h>

#include "tcp_connection.h"
#include "tcpip/tcpip.h"

namespace ag {

/**
 * Initializes TCP callbacks module
 *
 * @param ctx pointer to TCP context instance
 *
 * @return     pointer to TUN TCP control block instance, or
 *             NULL if something went wrong
 */
err_t tcp_raw_init(TcpipCtx *ctx);

/**
 * Deinitializes TCP callbacks module
 *
 * @param ctx pointer to TCPIP context instance
 */
void tcp_raw_destroy(TcpipCtx *ctx);

/**
 * Sends given data via LWIP's TCP service
 *
 * @param pcb pointer to TCP control block
 * @param data pointer to buffer with data to be sent
 * @param size size of the data
 */
err_t tcp_raw_send(struct tcp_pcb *pcb, const uint8_t *data, const size_t size);

/**
 * Closes LWIP TCP connection
 *
 * @param pcb pointer to TCP control block
 */
void tcp_raw_close(struct tcp_pcb *pcb, bool graceful);

/**
 * Says how many bytes in output buffer is available for sending
 *
 * @param pcb pointer to TCP control block
 *
 * @return     Number of bytes in output buffer is available
 */
size_t tcp_raw_get_out_buf_space(const struct tcp_pcb *pcb);

/**
 * Increases TCP window size
 *
 * @param pcb pointer to TCP control block
 * @param sent number of bytes were sent
 */
void tcp_raw_slide_window(struct tcp_pcb *pcb, const size_t sent);

} // namespace ag
