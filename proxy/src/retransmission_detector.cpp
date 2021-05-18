#include "retransmission_detector.h"

int ag::retransmission_detector::register_packet(uint16_t pkt_id, const socket_address &peername) {
    std::scoped_lock l(mtx);
    return ++(count_map[(request_key){pkt_id, peername}]);
}

int ag::retransmission_detector::deregister_packet(uint16_t pkt_id, const socket_address &peername) {
    std::scoped_lock l(mtx);
    auto it = count_map.find((request_key){pkt_id, peername});
    if (it == count_map.end()) {
        return 0;
    }
    int count = it->second;
    count_map.erase(it);
    return count;
}
