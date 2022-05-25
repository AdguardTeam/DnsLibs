#pragma once

#include <cstddef>
#include "common/defs.h"

namespace ag::dnscrypt {

/**
 * Add padding to packet
 * @param[in,out] packet Packet to pad
 * @param min_size Minimum size of packet
 * @return Error optional if failed
 */
ErrString pad(Uint8Vector &packet, size_t min_size);

/**
 * Remove padding from packet
 * @param[in,out] packet Packet to unpad
 * @return Error optional if failed
 */
ErrString unpad(Uint8Vector &packet);

} // namespace ag::dnscrypt
