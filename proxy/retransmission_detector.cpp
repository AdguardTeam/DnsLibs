#include "retransmission_detector.h"

namespace ag::dns {

int RetransmissionDetector::register_packet(uint16_t pkt_id, const SocketAddress &peername) {
    std::scoped_lock l(m_mtx);
    return ++(m_count_map[retransmission_detector::RequestKey{pkt_id, peername}]);
}

int RetransmissionDetector::deregister_packet(uint16_t pkt_id, const SocketAddress &peername) {
    std::scoped_lock l(m_mtx);
    auto it = m_count_map.find(retransmission_detector::RequestKey{pkt_id, peername});
    if (it == m_count_map.end()) {
        return 0;
    }
    int count = it->second;
    m_count_map.erase(it);
    return count;
}

} // namespace ag::dns
