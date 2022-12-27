#pragma once

#include "common/error.h"
#include "common/utils.h"

namespace ag {
namespace dns {

using ErrString = std::optional<std::string>;

/**
 * Enum for errors than can happen during DNS exchange
 */
enum DnsError {
    DE_ENCODE_ERROR,
    DE_DECODE_ERROR,
    DE_ENCRYPT_ERROR,
    DE_DECRYPT_ERROR,

    DE_BOOTSTRAP_ERROR,
    DE_HANDSHAKE_ERROR,

    DE_REPLY_PACKET_ID_MISMATCH,
    DE_REQUEST_PACKET_TOO_SHORT,
    DE_RESPONSE_PACKET_TOO_SHORT,
    DE_TRUNCATED_RESPONSE,
    DE_NESTED_DNS_ERROR,
    DE_CURL_ERROR,
    DE_BAD_RESPONSE,

    DE_SOCKET_ERROR,
    DE_OUTBOUND_PROXY_ERROR,
    DE_CONNECTION_CLOSED,
    DE_INTERNAL_ERROR,
    DE_TIMED_OUT,

    DE_SHUTTING_DOWN,
};

} // namespace dns

template<>
struct ErrorCodeToString<dns::DnsError> {
    std::string operator()(dns::DnsError e) {
        switch (e) {
        case dns::DE_ENCODE_ERROR: return "Can't encode request";
        case dns::DE_DECODE_ERROR: return "Can't decode reply";
        case dns::DE_ENCRYPT_ERROR: return "Error encrypting query for server";
        case dns::DE_DECRYPT_ERROR: return "Error decrypting server reply";
        case dns::DE_BOOTSTRAP_ERROR: return "Failed to resolve address of DNS server";
        case dns::DE_HANDSHAKE_ERROR: return "Error while handshaking to server";
        case dns::DE_REPLY_PACKET_ID_MISMATCH: return "Packet ID of reply doesn't match request";
        case dns::DE_REQUEST_PACKET_TOO_SHORT: return "Request packet too short";
        case dns::DE_RESPONSE_PACKET_TOO_SHORT: return "Response packet too short";
        case dns::DE_TRUNCATED_RESPONSE: return "Response was truncated";
        case dns::DE_NESTED_DNS_ERROR: return "Nested DNS request failed";
        case dns::DE_CURL_ERROR: return "CURL request failed";
        case dns::DE_BAD_RESPONSE: return "Bad response";
        case dns::DE_SOCKET_ERROR: return "Socket error";
        case dns::DE_OUTBOUND_PROXY_ERROR: return "Couldn't connect to outbound proxy";
        case dns::DE_CONNECTION_CLOSED: return "Connection error";
        case dns::DE_INTERNAL_ERROR: return "Internal error";
        case dns::DE_TIMED_OUT: return "Timed out";
        case dns::DE_SHUTTING_DOWN: return "Shutting down";
        default: return AG_FMT("Unknown error: {}", int(e));
        }
    };
};

} // namespace ag
