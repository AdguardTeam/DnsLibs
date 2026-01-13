#pragma once

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <vector>

#include "common/socket_address.h"
#include "platform.h"

namespace ag {

// Default values for `TcpFlowCtrlInfo` if there is no way to get real values
#define DEFAULT_SEND_WINDOW_SIZE (8 * 1024 * 1024)

// For use in C interfaces. `uint32_t` to make it easier for C# bindings.
#define AG_ARRAY_OF(T)                                                                                                 \
    struct {                                                                                                           \
        T *data;                                                                                                       \
        uint32_t size;                                                                                                 \
    }

typedef struct {
    uint8_t *data;
    size_t size;
    void (*destructor)(void *destructor_arg, uint8_t *data);
    void *destructor_arg;
} Packet;

typedef AG_ARRAY_OF(Packet) Packets;

class PacketsHolder {
public:
    PacketsHolder() = default;
    explicit PacketsHolder(Packets packets)
            : m_packets(packets.data, packets.data + packets.size)
    {}
    ~PacketsHolder() {
        for (auto p : m_packets) {
            if (p.destructor) {
                p.destructor(p.destructor_arg, p.data);
            }
        }
    }
    std::vector<Packet> release() {
        std::vector<Packet> ret = std::move(m_packets);
        return ret;
    }
    void add(Packet packet) {
        m_packets.push_back(packet);
    }
    void add(Packets packets) {
        std::copy(packets.data, packets.data + packets.size, std::back_inserter(m_packets));
    }

    PacketsHolder(const PacketsHolder &) = delete;
    void operator=(const PacketsHolder &) = delete;
    PacketsHolder(PacketsHolder &&other) noexcept {
        *this = std::move(other);
    }
    PacketsHolder &operator=(PacketsHolder &&other) noexcept {
        std::swap(m_packets, other.m_packets);
        return *this;
    }
private:
    std::vector<Packet> m_packets;
};



/**
 * Combine 2 hash codes into a single one
 */
inline uint64_t hash_pair_combine(uint64_t h1, uint64_t h2) {
    uint64_t hash = 17;
    hash = hash * 31 + h1;
    hash = hash * 31 + h2;
    return hash;
}

/**
 * Get hash of IP address
 */
inline uint64_t ip_addr_hash(sa_family_t family, const void *addr) {
    uint64_t hash = 0;

    switch (family) {
    case AF_INET:
        std::memcpy(&hash, addr, sizeof(uint32_t));
        break;
    case AF_INET6: {
        uint64_t ip_1;
        uint64_t ip_2;
        std::memcpy(&ip_1, addr, sizeof(ip_1));
        std::memcpy(&ip_2, (const uint8_t *) addr + sizeof(ip_1), sizeof(ip_2));
        hash = hash_pair_combine(ip_1, ip_2);
        break;
    }
    }

    return hash;
}


enum IcmpMessageType {
    ICMP_MT_ECHO_REPLY = 0,              // Echo Reply Message
    ICMP_MT_DESTINATION_UNREACHABLE = 3, // Destination Unreachable Message
    ICMP_MT_ECHO = 8,                    // Echo Message
    ICMP_MT_TIME_EXCEEDED = 11,          // Time Exceeded Message
};

enum Icmpv6MessageType {
    ICMPV6_MT_DESTINATION_UNREACHABLE = 1, // Destination Unreachable Message
    ICMPV6_MT_TIME_EXCEEDED = 3,           // Time Exceeded Message
    ICMPV6_MT_ECHO_REQUEST = 128,          // Echo Request Message
    ICMPV6_MT_ECHO_REPLY = 129,            // Echo Reply Message
};

/**
 * Special message type used as a marker for dropping a pending request.
 * The value must not match any of the standard codes from
 * https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml.
 */
constexpr uint8_t ICMP_MT_DROP = 84;

struct TcpFlowCtrlInfo {
    size_t send_buffer_size; // free space in a connection write buffer
    size_t send_window_size; // size of a connection send window
};

struct IcmpEchoRequest {
    SocketAddress peer; /**< destination address of connection */
    uint16_t id;        /**< an identifier to aid in matching echos and replies */
    uint16_t seqno;     /**< a sequence number to aid in matching echos and replies */
    uint8_t ttl;        /**< a carrying IP packet TTL */
    uint16_t data_size; /**< the size of data of the echo message */
};

struct IcmpEchoReply {
    /** source address of the reply (essentially equals to `dst` in corresponding `tcpip_icmp_echo_t`) */
    SocketAddress  peer;
    uint16_t id;    /**< an identifier to aid in matching echos and replies */
    uint16_t seqno; /**< a sequence number to aid in matching echos and replies */
    uint8_t type;   /**< a type of the reply message */
    uint8_t code;   /**< a code of the reply message */
};

struct IcmpEchoRequestEvent {
    IcmpEchoRequest request;
    int result; /**< operation result - filled by caller: 0 if successful, non-zero otherwise */
};

} // namespace ag
