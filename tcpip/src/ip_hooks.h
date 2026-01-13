#pragma once

#include <lwip/ip_addr.h>
#include <lwip/netif.h>
#include <lwip/pbuf.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * IPv4 input hook for LWIP.
 * Used to disable LWIP routing logic and to allow custom hooks for TCP, UDP and ICMP
 * @param p Input packet
 * @param inp Input interface
 * @return True if packet is eaten, false if packet must be forwarded to LWIP
 */
int ip4_input_hook(struct pbuf *p, struct netif *inp);

/**
 * IPv6 input hook for LWIP
 * Used to disable LWIP routing logic and to allow use custom hooks for TCP, UDP and ICMP
 * @param p Input packet
 * @param inp Input interface
 * @return True if packet is eaten, false if packet must be forwarded to LWIP
 */
int ip6_input_hook(struct pbuf *p, struct netif *inp);

#define LWIP_HOOK_IP4_INPUT(p, inp) ip4_input_hook((p), (inp))
#define LWIP_HOOK_IP6_INPUT(p, inp) ip6_input_hook((p), (inp))

#ifdef __cplusplus
} // extern "C"
#endif
