#pragma once

#include <ag_defs.h>
#include <upstream.h>

namespace ag::dns64 {

using discovery_result = std::pair<std::vector<uint8_vector>, err_string>;
using ipv6_synth_result = std::pair<uint8_array<16>, err_string>;
using prefixes = std::shared_ptr<with_mtx<std::vector<ag::uint8_vector>>>;

/**
 * Discover DNS64 presence.
 * @param upstream The upstream to query for DNS64 prefixes.
 * @return Unique prefixes, in the same order as returned by the upstream. Empty vector if no prefixes were found.
 */
discovery_result discover_prefixes(const upstream_ptr &upstream);

/**
 * Make an IPv4-embedded IPv6 address using the specified prefix. Returns all zeros if there was an error (see params).
 * @param prefix The prefix to use. Must be valid.
 * @param ip4    The IPv4 address to embed. In network order. Must be of correct length.
 * @return The synthesized address, all zeroes if there was an error.
 */
ipv6_synth_result synthesize_ipv4_embedded_ipv6_address(uint8_view prefix, uint8_view ip4);

} // namespace ag::dns64
