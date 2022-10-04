#pragma once

#include "common/coro.h"
#include "common/defs.h"
#include "common/error.h"
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

} // namespace ag::dns
