#pragma once

#include <stdint.h>

#include "lwipopts.h" // Include before LWIP headers

#include <khash.h>
#include <lwip/prot/icmp.h>
#include <lwip/prot/icmp6.h>

#include "common/logger.h"
#include "icmp_request.h"
#include "tcpip/tcpip.h"

namespace ag {

KHASH_INIT(icmp_requests, IcmpRequestKey *, IcmpRequestDescriptor *, 1, icmp_request_key_hash, icmp_request_key_equals)

typedef struct IcmpCtx {
    khash_t(icmp_requests) * requests;
    ag::Logger log{"TCPIP.ICMPMNGR"};
} IcmpCtx;

/**
 * Init ICMP request manager
 * @return true if successful
 */
bool icmp_rm_init(TcpipCtx *ctx);

/**
 * Close ICMP request manager
 */
void icmp_rm_close(TcpipCtx *ctx);

/**
 * Cleanup ICMP request manager
 */
void icmp_rm_clean_up(TcpipCtx *ctx);

/**
 * Find descriptor in given list by ICMP id-seqno pair
 * @return non-null if found
 */
IcmpRequestDescriptor *icmp_rm_find_descriptor(const TcpipCtx *ctx, u16_t id, u16_t seqno);

/**
 * Create an ICMP request descriptor
 * @param ctx TCP/IP context
 * @param src Packet source
 * @param dst Packet destination
 * @param id ICMP echo request id
 * @param seqno ICMP echo request sequence number
 * @param ttl ICMP echo request ttl
 * @param buffer input packet
 * @return non-null if successful
 */
IcmpRequestDescriptor *icmp_rm_create_descriptor(TcpipCtx *ctx, const ip_addr_t *src, const ip_addr_t *dst, u16_t id,
        u16_t seqno, u16_t ttl, struct pbuf *buffer);

/**
 * Close ICMP request descriptor
 */
void icmp_rm_close_descriptor(TcpipCtx *ctx, IcmpRequestDescriptor *request);

/**
 * Start ICMP request
 * @return 0 if successfully started, non-zero otherwise (in that case packet should be dropped)
 */
int icmp_rm_start_request(TcpipCtx *ctx, IcmpRequestDescriptor *request);

/**
 * Process ICMP reply
 */
void icmp_rm_process_reply(TcpipCtx *ctx, const IcmpEchoReply *reply);

} // namespace ag
