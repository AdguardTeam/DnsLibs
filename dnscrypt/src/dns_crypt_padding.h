#pragma once

#include <cstddef>
#include <ag_defs.h>

namespace ag::dnscrypt {

/**
 * Add padding to packet
 * @param[in,out] packet Packet to pad
 * @param min_size Minimum size of packet
 * @return Error optional if failed
 */
err_string pad(uint8_vector &packet, size_t min_size);

/**
 * Remove padding from packet
 * @param[in,out] packet Packet to unpad
 * @return Error optional if failed
 */
err_string unpad(uint8_vector &packet);

} // namespace ag::dnscrypt
