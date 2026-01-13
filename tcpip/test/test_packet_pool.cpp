#include <gtest/gtest.h>

#include "packet_pool.h"

using namespace ag;

TEST(PacketPool, Functional){
    const size_t pool_capacity = 20;
    std::unique_ptr<PacketPool> pool{new PacketPool(pool_capacity, DEFAULT_MTU_SIZE)};
    std::vector<Packet> packets;
    Packet packet = pool->get_packet();

    ASSERT_EQ(pool->get_size(), 19);
    pool->return_packet_data(packet.data);
    ASSERT_EQ(pool->get_size(), 20);

    for (auto i = 0; i < 20; ++i) {
        packets.push_back(pool->get_packet());
    }
    ASSERT_EQ(pool->get_size(), 0);
    for (auto i = 0; i < 5; ++i) {
        packets.push_back(pool->get_packet());
    }

    // ensure that we didn't increase size of data blocks
    for (auto &p : packets) {
        pool->return_packet_data(p.data);
    }
    ASSERT_EQ(pool->get_size(), pool_capacity);
}
