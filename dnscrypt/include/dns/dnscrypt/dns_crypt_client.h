#pragma once

#include <chrono>
#include <string_view>
#include <ldns/packet.h>

#include "common/defs.h"
#include "dns/common/dns_defs.h"
#include "dns/dnscrypt/dns_crypt_server_info.h"
#include "dns/dnscrypt/dns_crypt_utils.h"
#include "dns/dnsstamp/dns_stamp.h"
#include "dns/net/socket.h"

namespace ag::dns::dnscrypt {

/**
 * Client contains parameters for a DNSCrypt client
 */
class Client {
public:
    enum class DialError {
        AE_STAMP_PARSE_ERROR,
        AE_BAD_PROTOCOL,
        AE_KEYPAIR_GENERATION_ERROR,
        AE_EMPTY_PROVIDER_NAME,
        AE_FETCH_DNSCRYPT_CERT_ERROR,
    };
    struct DialInfo {
        ServerInfo server;
        Millis round_trip_time;
    };
    using DialResult = Result<DialInfo, DialError>;

    struct ExchangeInfo {
        ldns_pkt_ptr packet;
        Millis round_trip_time;
    };
    using ExchangeResult = Result<ExchangeInfo, DnsError>;

    static constexpr auto DEFAULT_PROTOCOL = utils::TP_UDP;
    static constexpr Millis DEFAULT_TIMEOUT{0};

    /**
     * Client constructor
     * @param protocol
     * @param adjust_payload_size If true, the client will automatically add a EDNS0 RR that will advertise
     *                            a larger buffer
     */
    explicit Client(utils::TransportProtocol protocol = DEFAULT_PROTOCOL);

    /**
     * Dial fetches and validates DNSCrypt certificate from the given server
     * Data received during this call is then used for DNS requests encryption/decryption
     * @param stamp_str Stamp string is an sdns:// address which is parsed using dnsstamps library
     * @param loop Event loop
     * @param timeout Timeout for read/write operations (0 means infinite timeout)
     * @param socket_factory Socket factory which creates sockets for data exchange
     * @param socket_parameters Connection socket parameters (the `proto` field is ignored)
     */
    coro::Task<DialResult> dial(std::string_view stamp_str, EventLoop &loop, Millis timeout,
            const SocketFactory *socket_factory, SocketFactory::SocketParameters socket_parameters) const;

     /**
      * Dial fetches and validates DNSCrypt certificate from the given server
      * Data received during this call is then used for DNS requests encryption/decryption
      * @param stamp Stamp
      * @param loop Event loop
      * @param timeout Timeout for read/write operations (0 means infinite timeout)
      * @param socket_factory Socket factory which creates sockets for data exchange
      * @param socket_parameters Connection socket parameters (the `proto` field is ignored)
      */
    coro::Task<DialResult> dial(const ServerStamp &stamp, EventLoop &loop, Millis timeout,
            const SocketFactory *socket_factory, SocketFactory::SocketParameters socket_parameters) const;

    /**
     * Exchange performs a synchronous DNS query to the specified DNSCrypt server and returns a DNS response.
     * This method creates a new network connection for every call so avoid using it for TCP.
     * DNSCrypt server information needs to be fetched and validated prior to this call using the c.DialStamp method.
     * @param message Message to send
     * @param server_info Server info
     * @param loop Event loop
     * @param timeout Timeout for read/write operations (0 means infinite timeout)
     * @param socket_factory Socket factory which creates sockets for data exchange
     * @param socket_parameters Connection socket parameters (the `proto` field is ignored)
     * @return Result of exchange
     */
    coro::Task<ExchangeResult> exchange(const ldns_pkt &message, const ServerInfo &server_info, EventLoop &loop,
            Millis timeout, const SocketFactory *socket_factory,
            SocketFactory::SocketParameters socket_parameters) const;

private:
    utils::TransportProtocol m_protocol;
};

} // namespace ag::dns::dnscrypt

namespace ag {

// clang format off
template<>
struct ErrorCodeToString<ag::dns::dnscrypt::Client::DialError> {
    std::string operator()(ag::dns::dnscrypt::Client::DialError e) {
        switch(e) {
        case decltype(e)::AE_STAMP_PARSE_ERROR: return "Failed to parse DNS stamp";
        case decltype(e)::AE_BAD_PROTOCOL: return "Stamp is not for a DNSCrypt server";
        case decltype(e)::AE_KEYPAIR_GENERATION_ERROR: return "Can not generate keypair";
        case decltype(e)::AE_EMPTY_PROVIDER_NAME: return "Provider name is empty";
        case decltype(e)::AE_FETCH_DNSCRYPT_CERT_ERROR: return "Error fetching DNSCrypt cert";
        }
    }
};
// clang format on

} // namespace ag
