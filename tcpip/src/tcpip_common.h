#pragma once

#include <stdint.h>
#include <stdlib.h>

#include "lwipopts.h" // Include before LWIP headers

#include <lwip/ip_addr.h>
#include <lwip/prot/tcp.h>

#include "common/logger.h"
#include "dns/common/uv_wrapper.h"
#include "icmp_request_manager.h"
#include "packet_pool.h"
#include "tcp_conn_manager.h"
#include "tcpip/platform.h"
#include "tcpip/tcpip.h"
#include "tcpip/utils.h"
#include "udp_conn_manager.h"

#define CATCH_ANY_PORT 0xffffu

namespace ag {

struct TcpipCtx {
    TcpipParameters parameters;     /**< Parameters of TCP/IP stack */
    uint8_t *tun_input_buffer;      /**< Buffer for incoming data of TUN device */
    dns::UvPtr<uv_poll_t> tun_poll; /**< Poll handle for TUN data handling */
    dns::UvPtr<uv_timer_t> timer;   /**< General timer handle */
    TcpCtx tcp;                     /**< TCP connections context */
    UdpCtx udp;                     /**< UDP connections context */
    IcmpCtx icmp;                   /**< ICMP requests context */
    struct netif *netif;            /**< Network interface */
    int pcap_fd;                    /**< PCap output file descriptor */
    PacketPool *pool;               /**< Pool with pre-allocated data blocks for Packets */
    ag::Logger logger{"TCPIP.COMMON"};
};

typedef void (*TimerTickNotifyFn)(TcpipCtx *ctx);

/**
 * Private TCP/IP initialize function
 *
 * @param params pointer to TCP/IP parameters structure
 *
 * @return     Pointer to context of successfully created connection, or
 *             NULL if something gone wrong
 */
TcpipCtx *tcpip_init_internal(const TcpipParameters *params);

/**
 * Private TCP/IP close function
 *
 * @param ctx pointer to context of connection returned by `tcpip_open`
 */
void tcpip_close_internal(TcpipCtx *ctx);

/**
 * Updates timeout for connection
 *
 * @param ctx pointer to TCP/IP context
 * @param connection connection
 * @param seconds connection timeout in seconds
 */
void tcpip_refresh_connection_timeout_with_interval(TcpipCtx *ctx, TcpipConnection *connection, time_t seconds);

/**
 * Updates timeout for connection
 *
 * @param ctx pointer to TCP/IP context
 * @param connection connection
 */
void tcpip_refresh_connection_timeout(TcpipCtx *ctx, TcpipConnection *connection);

/**
 * Passes incoming packet to native TCP/IP stack and waits synchronously while they'll be processed
 * @param ctx pointer to context of TCP/IP stack
 * @param packets Array of incoming packet's buffers (one buffer - one packet)
 */
void tcpip_process_input_packets(TcpipCtx *ctx, Packets *packets);

TcpipConnection *tcpip_get_connection_by_id(const ConnectionTables *tables, uint64_t id);

TcpipConnection *tcpip_get_connection_by_ip(const ConnectionTables *tables, const ip_addr_t *src_addr,
        uint16_t src_port, const ip_addr_t *dst_addr, uint16_t dst_port);

int tcpip_put_connection(ConnectionTables *tables, TcpipConnection *connection);

void tcpip_remove_connection(ConnectionTables *tables, TcpipConnection *connection);

uint64_t lwip_ip_addr_hash(const ip_addr_t *addr);

} // namespace ag
