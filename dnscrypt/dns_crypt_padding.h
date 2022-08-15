#pragma once

#include <cstddef>
#include "common/defs.h"

namespace ag::dns::dnscrypt {

/**
 * Add padding to packet
 * @param[in,out] packet Packet to pad
 * @param min_size Minimum size of packet
 * @return True on success
 */
bool pad(Uint8Vector &packet, size_t min_size);

/**
 * Remove padding from packet
 * @param[in,out] packet Packet to unpad
 * @return True on success
 */
bool unpad(Uint8Vector &packet);

} // namespace ag::dns::dnscrypt
