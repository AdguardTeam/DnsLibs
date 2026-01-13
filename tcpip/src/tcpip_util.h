#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <uv.h>

#include <lwip/ip_addr.h>

#include "common/socket_address.h"
#include "tcpip/platform.h"

namespace ag {

/**
 * Convert ip_addr_t and port to `SocketAddress`
 *
 * @param addr ip_addr_t instance
 * @param port Port
 * @param out_sock_addr SocketAddress
 */
SocketAddress ip_addr_to_socket_address(const ip_addr_t *addr, uint16_t port);

/**
 * Makes ip_addr_t and port from SocketAddress
 * @param sock_addr SocketAddress
 * @param out_addr ip_addr_t instance
 * @param out_port port
 */
void socket_address_to_ip_addr(const SocketAddress &sock_addr, ip_addr_t *out_addr, uint16_t *out_port);

/**
 * IP addr to string conversion, prettier than LWIP variant
 * @param addr IP address
 * @param buf Output buffer
 * @param buflen Output buffer length
 */
void ipaddr_ntoa_r_pretty(const ip_addr_t *addr, char *buf, int buflen);


/**
 * Writes pcap file header
 * @param fd File descriptor
 * @return 0 on success
 */
int pcap_write_header(int fd);

/**
 * Writes packet to pcap file
 * @param fd File descriptor
 * @param tv Timestamp
 * @param data Packet data
 * @param len Packet length
 * @return 0 on success
 */
int pcap_write_packet(int fd, struct timeval *tv, const void *data, size_t len);

/**
 * Writes packet to pcap file from uv_buf_t array
 * @param fd File descriptor
 * @param tv Timestamp
 * @param buf libuv buffer array
 * @param buf_cnt Number of buffers
 * @return 0 on success
 */
int pcap_write_packet_uv_buf(int fd, struct timeval *tv, const uv_buf_t *buf, int buf_cnt);

/**
 * Calculates approximate size of headers sent with useful payload
 *
 * @param bytes_transfered size of useful data sent
 * @param proto_id id of the transport protocol (UDP or TCP)
 * @param mtu_size size of maximum transfer unit for stack
 *
 * @return size of sent headers
 */
size_t get_approx_headers_size(size_t bytes_transfered, uint8_t proto_id, uint16_t mtu_size);

} // namespace ag
