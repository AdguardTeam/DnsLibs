#pragma once

#include "common/socket_address.h"
#include "common/utils.h"
#include <mutex>
#include <unordered_map>

namespace ag::dns::retransmission_detector {

struct RequestKey {
    uint16_t id; // Request ID
    SocketAddress peername; // Requestor address

    bool operator==(const RequestKey &other) const {
        return id == other.id && peername == other.peername;
    }
};
} // namespace ag::dns

namespace std {
template<>
struct hash<ag::dns::retransmission_detector::RequestKey> {
    size_t operator()(const ag::dns::retransmission_detector::RequestKey &key) const {
        return ag::utils::hash_combine(key.id, key.peername);
    }
};
} // namespace std

namespace ag::dns {

class RetransmissionDetector {
public:
    /**
     * Return the number of times this packet has been registered,
     * including this one, so the minimum returned count is 1.
     */
    int register_packet(uint16_t pkt_id, const SocketAddress &peername);

    /**
     * Reset registered count of the packet to 0. Return the last value of count.
     */
    int deregister_packet(uint16_t pkt_id, const SocketAddress &peername);

private:
    std::mutex m_mtx;
    std::unordered_map<retransmission_detector::RequestKey, int> m_count_map; // value is never 0: incremented on insertion
};

} // namespace ag::dns
