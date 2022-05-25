#pragma once

#include <chrono>
#include <string_view>
#include <ldns/packet.h>
#include "common/defs.h"
#include "dns_crypt_server_info.h"
#include "dns_crypt_utils.h"
#include "dnsstamp/dns_stamp.h"
#include "net/socket.h"

namespace ag::dnscrypt {

/**
 * Client contains parameters for a DNSCrypt client
 */
class Client {
public:
    struct DialResult {
        ServerInfo server;
        Millis round_trip_time;
        ErrString error;
    };
    struct ExchangeResult {
        ldns_pkt_ptr packet;
        Millis round_trip_time;
        ErrString error;
    };

    static constexpr auto DEFAULT_PROTOCOL = utils::TP_UDP;
    static constexpr Millis DEFAULT_TIMEOUT{0};
    static constexpr auto DEFAULT_ADJUST_PAYLOAD_SIZE = false;

    /**
     * Client constructor with default UDP protocol
     * @param adjust_payload_size If true, the client will automatically add a EDNS0 RR that will advertise
     *                            a larger buffer
     */
    explicit Client(bool adjust_payload_size = DEFAULT_ADJUST_PAYLOAD_SIZE);

    /**
     * Client constructor
     * @param protocol
     * @param adjust_payload_size If true, the client will automatically add a EDNS0 RR that will advertise
     *                            a larger buffer
     */
    explicit Client(utils::TransportProtocol protocol, bool adjust_payload_size = DEFAULT_ADJUST_PAYLOAD_SIZE);

    /**
     * Dial fetches and validates DNSCrypt certificate from the given server
     * Data received during this call is then used for DNS requests encryption/decryption
     * @param stamp_str Stamp string is an sdns:// address which is parsed using dnsstamps library
     * @param timeout Timeout for read/write operations (0 means infinite timeout)
     * @param socket_factory Socket factory which creates sockets for data exchange
     * @param socket_parameters Connection socket parameters (the `proto` field is ignored)
     */
    DialResult dial(std::string_view stamp_str, Millis timeout,
                    const SocketFactory *socket_factory, SocketFactory::SocketParameters socket_parameters) const;

     /**
      * Dial fetches and validates DNSCrypt certificate from the given server
      * Data received during this call is then used for DNS requests encryption/decryption
      * @param stamp Stamp
      * @param timeout Timeout for read/write operations (0 means infinite timeout)
      * @param socket_factory Socket factory which creates sockets for data exchange
      * @param socket_parameters Connection socket parameters (the `proto` field is ignored)
      */
    DialResult dial(const ServerStamp &stamp, Millis timeout,
                    const SocketFactory *socket_factory, SocketFactory::SocketParameters socket_parameters) const;

    /**
     * Exchange performs a synchronous DNS query to the specified DNSCrypt server and returns a DNS response.
     * This method creates a new network connection for every call so avoid using it for TCP.
     * DNSCrypt server information needs to be fetched and validated prior to this call using the c.DialStamp method.
     * @param message Message to send
     * @param server_info Server info
     * @param timeout Timeout for read/write operations (0 means infinite timeout)
     * @param socket_factory Socket factory which creates sockets for data exchange
     * @param socket_parameters Connection socket parameters (the `proto` field is ignored)
     * @return Result of exchange
     */
    ExchangeResult exchange(ldns_pkt &message, const ServerInfo &server_info,
                            Millis timeout,
                            const SocketFactory *socket_factory, SocketFactory::SocketParameters socket_parameters) const;

private:
    utils::TransportProtocol m_protocol;
    bool m_adjust_payload_size;
};

} // namespace ag::dnscrypt
