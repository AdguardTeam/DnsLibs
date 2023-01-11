#pragma once

#include "common/error.h"
#include "common/utils.h"

namespace ag {
namespace dns {

using ErrString = std::optional<std::string>;

/**
 * Enum for errors than can happen during DNS exchange
 */
enum class DnsError {
    AE_ENCODE_ERROR,
    AE_DECODE_ERROR,
    AE_ENCRYPT_ERROR,
    AE_DECRYPT_ERROR,

    AE_BOOTSTRAP_ERROR,
    AE_HANDSHAKE_ERROR,

    AE_REPLY_PACKET_ID_MISMATCH,
    AE_REQUEST_PACKET_TOO_SHORT,
    AE_RESPONSE_PACKET_TOO_SHORT,
    AE_TRUNCATED_RESPONSE,
    AE_NESTED_DNS_ERROR,
    AE_CURL_ERROR,
    AE_BAD_RESPONSE,

    AE_SOCKET_ERROR,
    AE_OUTBOUND_PROXY_ERROR,
    AE_CONNECTION_CLOSED,
    AE_INTERNAL_ERROR,
    AE_TIMED_OUT,

    AE_SHUTTING_DOWN,
    AE_EXCHANGE_ERROR,
};

/**
 * Enum for errors than can happen during DNS initialization
 */
enum class DnsProxyInitError {
    AE_PROXY_NOT_SET,
    AE_EVENT_LOOP_NOT_SET,
    AE_INVALID_ADDRESS,
    AE_EMPTY_PROXY,
    AE_PROTOCOL_ERROR,
    AE_LISTENER_INIT_ERROR,
    AE_INVALID_IPV4,
    AE_INVALID_IPV6,
    AE_UPSTREAM_INIT_ERROR,
    AE_FALLBACK_FILTER_INIT_ERROR,
    AE_FILTER_LOAD_ERROR,
    AE_MEM_LIMIT_REACHED,
    AE_NON_UNIQUE_FILTER_ID,
};

} // namespace dns

// clang format off
template<>
struct ErrorCodeToString<dns::DnsError> {
    std::string operator()(dns::DnsError e) {
        switch (e) {
        case decltype(e)::AE_ENCODE_ERROR: return "Can't encode request";
        case decltype(e)::AE_DECODE_ERROR: return "Can't decode reply";
        case decltype(e)::AE_ENCRYPT_ERROR: return "Error encrypting query for server";
        case decltype(e)::AE_DECRYPT_ERROR: return "Error decrypting server reply";
        case decltype(e)::AE_BOOTSTRAP_ERROR: return "Failed to resolve address of DNS server";
        case decltype(e)::AE_HANDSHAKE_ERROR: return "Error while handshaking to server";
        case decltype(e)::AE_REPLY_PACKET_ID_MISMATCH: return "Packet ID of reply doesn't match request";
        case decltype(e)::AE_REQUEST_PACKET_TOO_SHORT: return "Request packet too short";
        case decltype(e)::AE_RESPONSE_PACKET_TOO_SHORT: return "Response packet too short";
        case decltype(e)::AE_TRUNCATED_RESPONSE: return "Response was truncated";
        case decltype(e)::AE_NESTED_DNS_ERROR: return "Nested DNS request failed";
        case decltype(e)::AE_CURL_ERROR: return "CURL request failed";
        case decltype(e)::AE_BAD_RESPONSE: return "Bad response";
        case decltype(e)::AE_SOCKET_ERROR: return "Socket error";
        case decltype(e)::AE_OUTBOUND_PROXY_ERROR: return "Couldn't connect to outbound proxy";
        case decltype(e)::AE_CONNECTION_CLOSED: return "Connection error";
        case decltype(e)::AE_INTERNAL_ERROR: return "Internal error";
        case decltype(e)::AE_TIMED_OUT: return "Timed out";
        case decltype(e)::AE_SHUTTING_DOWN: return "Shutting down";
        case decltype(e)::AE_EXCHANGE_ERROR: return "Upstream exchange error";
        }
    };
};

template <>
struct ErrorCodeToString<ag::dns::DnsProxyInitError> {
    std::string operator()(ag::dns::DnsProxyInitError e) {
        switch (e) {
        case decltype(e)::AE_PROXY_NOT_SET: return "Proxy is not set";
        case decltype(e)::AE_EVENT_LOOP_NOT_SET: return "Event loop is not set";
        case decltype(e)::AE_INVALID_ADDRESS: return "Invalid address";
        case decltype(e)::AE_EMPTY_PROXY: return "DnsProxy is nullptr";
        case decltype(e)::AE_PROTOCOL_ERROR: return "Protocol is not implemented";
        case decltype(e)::AE_LISTENER_INIT_ERROR: return "Error was occured in DnsProxyListener initializing";
        case decltype(e)::AE_INVALID_IPV4: return "Invalid custom blocking IPv4 address";
        case decltype(e)::AE_INVALID_IPV6: return "Invalid custom blocking IPv6 address";
        case decltype(e)::AE_UPSTREAM_INIT_ERROR: return "Failed to initialize any upstream";
        case decltype(e)::AE_FALLBACK_FILTER_INIT_ERROR: return "Failed to initialize the fallback filtering module";
        case decltype(e)::AE_FILTER_LOAD_ERROR: return "Failed to load Filter";
        case decltype(e)::AE_MEM_LIMIT_REACHED: return "Filter added partially (reached memory limit)";
        case decltype(e)::AE_NON_UNIQUE_FILTER_ID: return "Non unique filter id";
        }
    }
};
// clang format on

} // namespace ag
