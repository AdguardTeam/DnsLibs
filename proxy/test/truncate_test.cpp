#include "common/defs.h"
#include <gtest/gtest.h>
#include <ldns/ldns.h>

#include "../dns_truncate.h"

namespace ag::dns::proxy::test {

#include "big_dns_packet.inc"

using ldns_pkt_ptr = UniquePtr<ldns_pkt, &ldns_pkt_free>;
using ldns_buffer_ptr = UniquePtr<ldns_buffer, &ldns_buffer_free>;

TEST(DnsTruncateTest, TruncateMinSize512) {
    Uint8View pkt_data = {&BIG_PACKET[0], std::size(BIG_PACKET) - 1};
    ASSERT_EQ(1946, pkt_data.size());

    ldns_pkt *pkt;
    ldns_status status = ldns_wire2pkt(&pkt, pkt_data.data(), pkt_data.size());
    ASSERT_EQ(LDNS_STATUS_OK, status) << ldns_get_errorstr_by_id(status);
    ldns_pkt_ptr pkt_guard{pkt};

    for (size_t max_size = 0; max_size < 256; ++max_size) {
        ldns_pkt_ptr pkt_tc{ldns_pkt_clone(pkt)};
        ASSERT_TRUE(dns::ldns_pkt_truncate(pkt_tc.get(), max_size));
        ldns_buffer_ptr buf{ldns_buffer_new(LDNS_MAX_PACKETLEN)};
        status = ldns_pkt2buffer_wire(buf.get(), pkt_tc.get());
        ASSERT_EQ(LDNS_STATUS_OK, status) << ldns_get_errorstr_by_id(status);
        ASSERT_GT(ldns_buffer_position(buf.get()), max_size);
        ASSERT_LE(ldns_buffer_position(buf.get()), 512);
    }
}

TEST(DnsTruncateTest, TruncateWorks) {
    Uint8View pkt_data = {&BIG_PACKET[0], std::size(BIG_PACKET) - 1};
    ASSERT_EQ(1946, pkt_data.size());

    ldns_pkt *pkt;
    ldns_status status = ldns_wire2pkt(&pkt, pkt_data.data(), pkt_data.size());
    ASSERT_EQ(LDNS_STATUS_OK, status) << ldns_get_errorstr_by_id(status);
    ldns_pkt_ptr pkt_guard{pkt};

    ASSERT_FALSE(ldns_pkt_tc(pkt));

    size_t prev_size = 0;
    for (size_t max_size = 512; max_size < pkt_data.size(); ++max_size) {
        ldns_pkt_ptr pkt_tc{ldns_pkt_clone(pkt)};

        // Might not truncate, but result could still be smaller due to compression
        bool truncated = dns::ldns_pkt_truncate(pkt_tc.get(), max_size);

        ldns_buffer_ptr buf{ldns_buffer_new(LDNS_MAX_PACKETLEN)};
        status = ldns_pkt2buffer_wire(buf.get(), pkt_tc.get());
        ASSERT_EQ(LDNS_STATUS_OK, status) << ldns_get_errorstr_by_id(status);

        ASSERT_LE(ldns_buffer_position(buf.get()), max_size);
        ASSERT_GE(ldns_buffer_position(buf.get()), prev_size);

        ldns_pkt *pkt_dec;
        status = ldns_wire2pkt(&pkt_dec, ldns_buffer_begin(buf.get()), ldns_buffer_position(buf.get()));
        ASSERT_EQ(LDNS_STATUS_OK, status) << ldns_get_errorstr_by_id(status);
        ldns_pkt_ptr guard{pkt_dec};

        ASSERT_EQ(ldns_pkt_tc(pkt_dec), truncated);
    }
}

} // namespace ag::dns::proxy::test
