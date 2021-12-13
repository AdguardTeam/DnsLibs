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
#include "common/defs.h"
#include <dns_crypt_utils.h>
#include <dns_stamp.h>
#include "common/socket_address.h"
#include <ag_socket.h>

namespace ag::dnscrypt {

using create_ldns_buffer_result = std::pair<ldns_buffer_ptr, ErrString>;
using create_ldns_pkt_result = std::pair<ldns_pkt_ptr, ErrString>;

struct dns_exchange_unparsed_result {
    std::vector<uint8_t> reply;
    std::chrono::milliseconds round_trip_time;
    ErrString error;
};

struct dns_exchange_result {
    ldns_pkt_ptr reply;
    std::chrono::milliseconds round_trip_time;
    ErrString error;
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
create_ldns_buffer_result create_ldns_buffer(const ldns_pkt &request_pkt);

/**
 * Create ldns packet from data with size
 * @param data Data
 * @param size Size
 * @return Ldns packet with copy of data with size
 */
create_ldns_pkt_result create_ldns_pkt(uint8_t *data, size_t size);

/**
 * Send data from buffer to the peer and return reply data
 * @param timeout Timeout for read/write operations (0 means infinite timeout)
 * @param socket_address Socket address
 * @param buffer Buffer to send
 * @param socket_factory Socket factory which creates sockets for data exchange
 * @param socket_parameters Connection socket parameters
 * @return DNS exchange allocated result
 */
dns_exchange_unparsed_result dns_exchange(std::chrono::milliseconds timeout,
        const SocketAddress &socket_address, ldns_buffer &buffer,
        const socket_factory *socket_factory, socket_factory::socket_parameters socket_parameters);

/**
 * Send data from buffer to socket address and returns ldns packet reply
 * @param timeout Timeout for read/write operations (0 means infinite timeout)
 * @param socket_address Socket address
 * @param buffer Buffer to send
 * @param socket_factory Socket factory which creates sockets for data exchange
 * @param socket_parameters Connection socket parameters
 * @return DNS exchange result
 */
dns_exchange_result dns_exchange_from_ldns_buffer(std::chrono::milliseconds timeout,
        const SocketAddress &socket_address, ldns_buffer &buffer,
        const socket_factory *socket_factory, socket_factory::socket_parameters socket_parameters);

/**
 * Send data from packet to socket address and returns ldns packet reply
 * @param timeout  Timeout for read/write operations (0 means infinite timeout)
 * @param socket_address Socket address
 * @param request_pkt Packet to send
 * @param socket_factory Socket factory which creates sockets for data exchange
 * @param socket_parameters Connection socket parameters
 * @return DNS exchange result
 */
dns_exchange_result dns_exchange_from_ldns_pkt(std::chrono::milliseconds timeout,
        const SocketAddress &socket_address, const ldns_pkt &request_pkt,
        const socket_factory *socket_factory, socket_factory::socket_parameters socket_parameters);

} // namespace ag::dnscrypt
