#pragma once

#include <stdint.h>

#include <lwip/ip_addr.h>
#include <lwip/pbuf.h>

#include "tcpip/tcpip.h"

namespace ag {

typedef struct {
    u16_t id;    /**< ICMP ECHO identifier */
    u16_t seqno; /**< ICMP ECHO sequence number */
} IcmpRequestKey;

typedef struct {
    IcmpRequestKey key;
    u8_t ttl;            /**< IP hop limit (TTL) */
    ip_addr_t src;       /**< Packet source */
    ip_addr_t dst;       /**< Packet destination */
    ip_addr_t reply_src; /**< Reply packet source */
    u8_t reply_type;     /**< ICMP reply message type */
    u8_t reply_code;     /**< ICMP reply message code */
    struct pbuf *buffer; /**< original ICMP echo packet */
} IcmpRequestDescriptor;

/**
 * Create an ICMP request key
 */
IcmpRequestKey icmp_request_key_create(u16_t id, u16_t seqno);

/**
 * Get hash of a key
 */
uint64_t icmp_request_key_hash(const IcmpRequestKey *key);

/**
 * Check whether 2 keys are equal
 */
bool icmp_request_key_equals(const IcmpRequestKey *lh, const IcmpRequestKey *rh);

/**
 * Create an ICMP request descriptor
 */
IcmpRequestDescriptor *icmp_request_create(
        const ip_addr_t *src, const ip_addr_t *dst, u16_t id, u16_t seqno, u8_t ttl, struct pbuf *buffer);

/**
 * Destroy an ICMP request descriptor
 */
void icmp_request_destroy(IcmpRequestDescriptor *request);

} // namespace ag
