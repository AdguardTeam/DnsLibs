#pragma once

#include "common/coro.h"
#include "common/defs.h"
#include "dns/upstream/upstream.h"

namespace ag::dns::dns64 {

enum class Ipv6SynthError {
    AE_INVALID_PREF64,
    AE_INVALID_IPV4
};

using DiscoveryResult = Result<std::vector<Uint8Vector>, DnsError>;
using Ipv6SynthResult = Result<Uint8Array<16>, Ipv6SynthError>;
using Prefixes = std::shared_ptr<WithMtx<std::vector<ag::Uint8Vector>>>;

/**
 * Discover DNS64 presence.
 * @param upstream The upstream to query for DNS64 prefixes.
 * @return Unique prefixes, in the same order as returned by the upstream. Empty vector if no prefixes were found.
 */
coro::Task<DiscoveryResult> discover_prefixes(const UpstreamPtr &upstream);

/**
 * Make an IPv4-embedded IPv6 address using the specified prefix. Returns all zeros if there was an error (see params).
 * @param prefix The prefix to use. Must be valid.
 * @param ip4    The IPv4 address to embed. In network order. Must be of correct length.
 * @return The synthesized address, all zeroes if there was an error.
 */
Ipv6SynthResult synthesize_ipv4_embedded_ipv6_address(Uint8View prefix, Uint8View ip4);

} // namespace ag::dns::dns64

namespace ag {

// clang format off
template<>
struct ErrorCodeToString<dns::dns64::Ipv6SynthError> {
    std::string operator()(dns::dns64::Ipv6SynthError e) {
        switch (e) {
        case decltype(e)::AE_INVALID_PREF64: return "Invalid Pref64::/n";
        case decltype(e)::AE_INVALID_IPV4: return "Invalid IPv4 addr";
        }
    }
};
// clang format on

} // namespace ag
