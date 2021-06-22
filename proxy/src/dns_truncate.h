#pragma once

#include <ag_defs.h>
#include <ldns/packet.h>

namespace ag {

using ldns_pkt_ptr = std::unique_ptr<ldns_pkt, ag::ftor<&ldns_pkt_free>>;

/**
 * Remove zero or more RRs from `pkt` so that the output of `ldns_pkt2buffer_wire` would not exceed `max_size`.
 * If any RRs are removed, the TC flag is set on `pkt`.
 * @return whether any RRs were removed
 */
bool ldns_pkt_truncate(ldns_pkt *pkt, uint16_t max_size);

} // namespace ag
