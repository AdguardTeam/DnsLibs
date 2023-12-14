#pragma once

#include "common/coro.h"
#include "common/defs.h"
#include "common/error.h"
#include "dns/common/dns_defs.h"
#include "dns/net/aio_socket.h"
#include "dns/net/socket.h"

namespace ag::dns {

/**
 * Send DNS packet to the peer
 * @param data the packet
 * @return Some error if failed
 */
[[nodiscard]] Error<SocketError> send_dns_packet(Socket *self, Uint8View data);

/**
 * Send DNS packet to the peer
 * @param data the packet
 * @return Some error if failed
 */
[[nodiscard]] Error<SocketError> send_dns_packet(AioSocket *self, Uint8View data);

/**
 * Receive DNS packet from the peer.
 * Blocks until either an error happened or the packet is fully received.
 * @param timeout operation timeout
 * @return The received packet if succeeded
 */
coro::Task<Result<Uint8Vector, SocketError>> receive_dns_packet(AioSocket *self, std::optional<Micros> timeout);

/**
 * Receive, decode, and validate a DNS packet from the peer.
 * Blocks until either an error occurred, an invalid packet is received, or a valid packet is fully received and decoded.
 * @param self AioSocket instance
 * @param timeout operation timeout
 * @param check_and_decode function to decode and validate the received packet
 * @return The received and decoded packet if succeeded and valid, nullptr otherwise
 */
coro::Task<Result<ldns_pkt_ptr, SocketError>> receive_and_decode_dns_packet(
        AioSocket *self,
        std::optional<Micros> timeout,
        std::function<ldns_pkt_ptr(Uint8Vector)> check_and_decode);
} // namespace ag::dns
