#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <functional>
#include <vector>
#include <ldns/buffer.h>
#include <ldns/error.h>
#include <ldns/packet.h>

#include "common/coro.h"
#include "common/defs.h"
#include "dns/common/dns_defs.h"
#include "common/socket_address.h"
#include "dns_crypt_utils.h"
#include "dns/dnsstamp/dns_stamp.h"
#include "dns/net/socket.h"

namespace ag::dns::dnscrypt {

using LdnsEncodeResult = Result<ldns_buffer_ptr, DnsError>;
using LdnsDecodeResult = Result<ldns_pkt_ptr, DnsError>;

struct DnsExchangeUnparsedResult {
    Uint8Vector reply;
    Millis round_trip_time;
    Error<DnsError> error;
};

struct DnsExchangeResult {
    ldns_pkt_ptr reply;
    Millis round_trip_time;
    Error<DnsError> error;
};

/**
 * Create request ldns packet using parameters
 * @param rr_type RR type
 * @param rr_class RR class
 * @param flags Packet flags
 * @param dname_str Dname string
 * @param size_opt Packet size optional
 * @return Ldns packet unique ptr, nullptr if error
 */
ldns_pkt_ptr create_request_ldns_pkt(ldns_rr_type rr_type, ldns_rr_class rr_class, uint16_t flags,
                                     std::string_view dname_str, std::optional<size_t> size_opt);

/**
 * Create ldns buffer from ldns packet
 * @param request_pkt Packet to convert
 * @return Ldns buffer converted from ldns packet
 */
LdnsEncodeResult create_ldns_buffer(const ldns_pkt &request_pkt);

/**
 * Create ldns packet from data with size
 * @param data Data
 * @param size Size
 * @return Ldns packet with copy of data with size
 */
LdnsDecodeResult create_ldns_pkt(uint8_t *data, size_t size);

/**
 * Send data from buffer to the peer and return reply data
 * @param loop Event loop
 * @param timeout Timeout for read/write operations (0 means infinite timeout)
 * @param socket_address Socket address
 * @param buffer Buffer to send
 * @param socket_factory Socket factory which creates sockets for data exchange
 * @param socket_parameters Connection socket parameters
 * @return DNS exchange allocated result
 */
coro::Task<DnsExchangeUnparsedResult> dns_exchange(EventLoop &loop, Millis timeout,
        const SocketAddress &socket_address, ldns_buffer &buffer,
        const SocketFactory *socket_factory, SocketFactory::SocketParameters socket_parameters);

/**
 * Send data from packet to socket address and returns ldns packet reply
 * @param loop Event loop
 * @param timeout  Timeout for read/write operations (0 means infinite timeout)
 * @param socket_address Socket address
 * @param request_pkt Packet to send
 * @param socket_factory Socket factory which creates sockets for data exchange
 * @param socket_parameters Connection socket parameters
 * @return DNS exchange result
 */
coro::Task<DnsExchangeResult> dns_exchange_from_ldns_pkt(EventLoop &loop, Millis timeout,
         const SocketAddress &socket_address, const ldns_pkt &request_pkt,
         const SocketFactory *socket_factory, SocketFactory::SocketParameters socket_parameters);

} // namespace ag::dns::dnscrypt
