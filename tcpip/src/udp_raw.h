#pragma once

#include <lwip/init.h>
#include <lwip/udp.h>

#include "tcpip/tcpip.h"
#include "udp_connection.h"

namespace ag {

/**
 * Initializes UDP raw module
 *
 * @param ctx TCPIP context instance
 *
 * @return     error code of operation
 */
err_t udp_raw_init(TcpipCtx *ctx);

/**
 * Sends given data via LWIP's UDP service
 *
 * @param descriptor UDP connection descriptor
 * @param from_ip source IP of datagram to be sent
 * @param from_port source port of datagram to be sent
 * @param data buffer with data to be sent
 * @param length size of the data
 */
err_t udp_raw_send(
        UdpConnDescriptor *descriptor, ip_addr_t *from_ip, uint16_t from_port, const uint8_t *data, size_t length);

/**
 * Closes activity on UDP raw module
 *
 * @param ctx TCPIP context instance
 */
void udp_raw_close(TcpipCtx *ctx);

} // namespace ag
