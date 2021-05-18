#pragma once

#include <ag_socket_address.h>
#include <ag_utils.h>
#include <mutex>
#include <unordered_map>

namespace ag {
struct request_key {
    uint16_t id; // Request ID
    ag::socket_address peername; // Requestor address

    bool operator==(const request_key &other) const {
        return id == other.id && peername == other.peername;
    }
};
} // namespace ag

namespace std {
template<>
struct hash<ag::request_key> {
    size_t operator()(const ag::request_key &key) const {
        return ag::utils::hash_combine(key.id, key.peername);
    }
};
} // namespace std

namespace ag {
class retransmission_detector {
public:
    /**
     * Return the number of times this packet has been registered,
     * including this one, so the minimum returned count is 1.
     */
    int register_packet(uint16_t pkt_id, const socket_address &peername);

    /**
     * Reset registered count of the packet to 0. Return the last value of count.
     */
    int deregister_packet(uint16_t pkt_id, const socket_address &peername);

private:
    std::mutex mtx;
    std::unordered_map<request_key, int> count_map; // value is never 0: incremented on insertion
};
} // namespace ag
