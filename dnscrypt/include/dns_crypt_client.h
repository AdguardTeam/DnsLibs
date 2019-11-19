#pragma once

#include <chrono>
#include <string_view>
#include <ldns/packet.h>
#include <ag_defs.h>
#include <dns_crypt_server_info.h>
#include <dns_crypt_utils.h>
#include <dns_stamp.h>

namespace ag::dnscrypt {

/**
 * Client contains parameters for a DNSCrypt client
 */
class client {
public:
    struct dial_result {
        server_info server_info;
        std::chrono::milliseconds round_trip_time;
        err_string error;
    };
    struct exchange_result {
        ldns_pkt_ptr packet;
        std::chrono::milliseconds round_trip_time;
        err_string error;
    };

    static constexpr auto DEFAULT_PROTOCOL = protocol::UDP;
    static constexpr std::chrono::milliseconds DEFAULT_TIMEOUT{0};
    static constexpr auto DEFAULT_ADJUST_PAYLOAD_SIZE = false;

    /**
     * Client constructor with default UDP protocol
     * @param timeout Timeout for read/write operations (0 means infinite timeout)
     * @param adjust_payload_size If true, the client will automatically add a EDNS0 RR that will advertise
     *                            a larger buffer
     */
    explicit client(std::chrono::milliseconds timeout = DEFAULT_TIMEOUT,
                    bool adjust_payload_size = DEFAULT_ADJUST_PAYLOAD_SIZE);

    /**
     * Client constructor
     * @param protocol
     * @param timeout Timeout for read/write operations (0 means infinite timeout)
     * @param adjust_payload_size If true, the client will automatically add a EDNS0 RR that will advertise
     *                            a larger buffer
     */
    explicit client(protocol protocol, std::chrono::milliseconds timeout = DEFAULT_TIMEOUT,
                    bool adjust_payload_size = DEFAULT_ADJUST_PAYLOAD_SIZE);

    /**
     * Dial fetches and validates DNSCrypt certificate from the given server
     * Data received during this call is then used for DNS requests encryption/decryption
     * @param stamp_str Stamp string is an sdns:// address which is parsed using dnsstamps library
     */
    dial_result dial(std::string_view stamp_str);

     /**
      * Dial fetches and validates DNSCrypt certificate from the given server
      * Data received during this call is then used for DNS requests encryption/decryption
      * @param stamp Stamp
      */
    dial_result dial(const server_stamp &stamp);

    /**
     * Exchange performs a synchronous DNS query to the specified DNSCrypt server and returns a DNS response.
     * This method creates a new network connection for every call so avoid using it for TCP.
     * DNSCrypt server information needs to be fetched and validated prior to this call using the c.DialStamp method.
     * @param message Message to send
     * @param server_info Server info
     * @return Result of exchange
     */
    exchange_result exchange(ldns_pkt &message, const server_info &server_info);

private:
    protocol m_protocol;
    std::chrono::milliseconds m_timeout;
    bool m_adjust_payload_size;
};

} // namespace ag::dnscrypt
