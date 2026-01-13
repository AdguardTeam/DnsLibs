#pragma once

#include <list>
#include <memory>

#include "tcpip/tcpip.h"
#include "tcpip/utils.h"

namespace ag {

class PacketPool {
public:
    /**
     * Init list with pointers to data blocks
     * @param size number of blocks
     * @param mtu size of one block
     */
    PacketPool(size_t size, int mtu);

    ~PacketPool();

    /**
     * Return Packet with pointer to data from pool.
     * If there are no unused data block, create the new one.
     */
    Packet get_packet();

    /**
     * Take ownership of allocated data back
     * @param packet pointer to data block
     */
    void return_packet_data(uint8_t *packet);

    /**
     * Return number of unused allocated blocks
     */
    int get_size();

private:
    struct PacketPoolState;

    size_t m_capacity;
    int m_mtu;
    std::list<std::unique_ptr<uint8_t[]>> m_packets;
    PacketPoolState *m_state;
};

} // namespace ag
