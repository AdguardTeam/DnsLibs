#pragma once

#include <chrono>
#include <string_view>
#include <ldns/packet.h>
#include <ag_defs.h>
#include <dns_crypt_server_info.h>
#include <dns_crypt_utils.h>
#include <dns_stamp.h>
#include <ag_socket.h>

namespace ag::dnscrypt {

/**
 * Client contains parameters for a DNSCrypt client
 */
class client {
public:
    struct dial_result {
        server_info server;
        std::chrono::milliseconds round_trip_time;
        err_string error;
    };
    struct exchange_result {
        ldns_pkt_ptr packet;
        std::chrono::milliseconds round_trip_time;
        err_string error;
    };

    static constexpr auto DEFAULT_PROTOCOL = utils::TP_UDP;
    static constexpr std::chrono::milliseconds DEFAULT_TIMEOUT{0};
    static constexpr auto DEFAULT_ADJUST_PAYLOAD_SIZE = false;

    /**
     * Client constructor with default UDP protocol
     * @param adjust_payload_size If true, the client will automatically add a EDNS0 RR that will advertise
     *                            a larger buffer
     */
    explicit client(bool adjust_payload_size = DEFAULT_ADJUST_PAYLOAD_SIZE);

    /**
     * Client constructor
     * @param protocol
     * @param adjust_payload_size If true, the client will automatically add a EDNS0 RR that will advertise
     *                            a larger buffer
     */
    explicit client(utils::transport_protocol protocol, bool adjust_payload_size = DEFAULT_ADJUST_PAYLOAD_SIZE);

    /**
     * Dial fetches and validates DNSCrypt certificate from the given server
     * Data received during this call is then used for DNS requests encryption/decryption
     * @param stamp_str Stamp string is an sdns:// address which is parsed using dnsstamps library
     * @param timeout Timeout for read/write operations (0 means infinite timeout)
     * @param socket_factory Socket factory which creates sockets for data exchange
     * @param outbound_interface Outbound interface info for communicating socket
     */
    dial_result dial(std::string_view stamp_str, std::chrono::milliseconds timeout,
            const socket_factory *socket_factory, const if_id_variant &outbound_interface) const;

     /**
      * Dial fetches and validates DNSCrypt certificate from the given server
      * Data received during this call is then used for DNS requests encryption/decryption
      * @param stamp Stamp
      * @param timeout Timeout for read/write operations (0 means infinite timeout)
      * @param socket_factory Socket factory which creates sockets for data exchange
      * @param outbound_interface Outbound interface info for communicating socket
      */
    dial_result dial(const server_stamp &stamp, std::chrono::milliseconds timeout,
            const socket_factory *socket_factory, const if_id_variant &outbound_interface) const;

    /**
     * Exchange performs a synchronous DNS query to the specified DNSCrypt server and returns a DNS response.
     * This method creates a new network connection for every call so avoid using it for TCP.
     * DNSCrypt server information needs to be fetched and validated prior to this call using the c.DialStamp method.
     * @param message Message to send
     * @param server_info Server info
     * @param timeout Timeout for read/write operations (0 means infinite timeout)
     * @param socket_factory Socket factory which creates sockets for data exchange
     * @param outbound_interface Outbound interface info for communicating socket
     * @return Result of exchange
     */
    exchange_result exchange(ldns_pkt &message, const server_info &server_info,
            std::chrono::milliseconds timeout, const socket_factory *socket_factory,
            const if_id_variant &outbound_interface) const;

private:
    utils::transport_protocol m_protocol;
    bool m_adjust_payload_size;
};

} // namespace ag::dnscrypt
