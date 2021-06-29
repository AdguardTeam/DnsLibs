#pragma once

#include <ldns/packet.h>

namespace ag {

/**
 * Remove zero or more RRs from `pkt` so that the output of `ldns_pkt2buffer_wire` would not exceed `max_size`.
 * If any RRs are removed, the TC flag is set on `pkt`.
 * @return whether any RRs were removed
 */
bool ldns_pkt_truncate(ldns_pkt *pkt, uint16_t max_size);

} // namespace ag
