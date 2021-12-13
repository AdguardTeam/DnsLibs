#include <dns64.h>
#include <vector>
#include <cassert>
#include <ldns/ldns.h>

// Well-known host used to discover dns64 presence
static constexpr auto WKN = "ipv4only.arpa.";

// Well-known ip4 addresses used in discovering the pref64
static constexpr uint8_t WKA0_BYTES[] = {192, 0, 0, 170};
static constexpr uint8_t WKA1_BYTES[] = {192, 0, 0, 171};

static constexpr ag::Uint8View WELL_KNOWN_ADDRESSES[] = {
        {WKA0_BYTES, std::size(WKA0_BYTES)},
        {WKA1_BYTES, std::size(WKA1_BYTES)}
};

static constexpr size_t IPV6_NULL_IDX = 8;

/**
 * Scans a synthesized IPv6 and extracts Pref64 (using the supplied well-known-address)
 * @param ip6 IPv4-embedded IPv6 synthesized address
 * @return the prefix, or empty vector if a valid prefix was not found
 */
static ag::Uint8Vector find_pref64(ag::Uint8View ip6, const ag::Uint8View wka) {
    assert(ip6.size() == LDNS_IP6ADDRLEN);
    assert(wka.size() == LDNS_IP4ADDRLEN);

    if (ip6[8] != 0) {
        // ip6 is invalid (RFC 6052 2.2)
        return {};
    }

    // Special case of Pref64::/96 (WKA is in last 4 bytes and occurs exactly once)
    auto first_occur = ip6.find(wka);
    if (first_occur == 12) {
        return {ip6.begin(), ip6.begin() + 12};
    }

    // With other prefix lengths, ip6 has a "hole" at position 8 (bits 64..71) (RFC 6052), ignore it
    auto vec = ag::utils::join<ag::Uint8Vector>(
            ag::Uint8View(ip6.data(), 8),
            ag::Uint8View(ip6.data() + 9, 7));

    // Replace view
    ip6 = ag::Uint8View(vec.data(), vec.size());

    first_occur = ip6.find(wka);
    auto last_occur = ip6.rfind(wka);

    if (first_occur != last_occur || first_occur == ag::Uint8View::npos || first_occur < 4 || first_occur > 8) {
        // WKA not found, or multiple occurrences found, or WKA found at an inappropriate location
        return {};
    }

    // Erase all but the prefix and return
    vec.erase(vec.begin() + first_occur, vec.end());
    return vec;
}

/**
 * Scans a synthesized IPv6 and extracts Pref64
 * @param ip6 IPv6 synthesized address
 * @return the prefix, or empty vector if a prefix was not found
 */
static ag::Uint8Vector find_pref64(const ag::Uint8View ip6) {
    for (const auto &wka : WELL_KNOWN_ADDRESSES) {
        const auto pref64 = find_pref64(ip6, wka);
        if (!pref64.empty()) {
            return pref64;
        }
    }

    return {};
}

ag::dns64::discovery_result ag::dns64::discover_prefixes(const ag::upstream_ptr &upstream) {
    ag::ldns_pkt_ptr pkt(
            ldns_pkt_query_new(
                    ldns_dname_new_frm_str(WKN),
                    LDNS_RR_TYPE_AAAA,
                    LDNS_RR_CLASS_IN,
                    LDNS_RD));

    // Must set CD to 0, otherwise the DNS64 server will not perform IPv6 address synthesis (Section 3 of [RFC6147])
    ldns_pkt_set_cd(pkt.get(), false);
    ldns_pkt_set_random_id(pkt.get());

    auto[reply, err] = upstream->exchange(pkt.get());

    if (err.has_value()) {
        return {{}, err};
    }

    std::vector<ag::Uint8Vector> result;
    const size_t cnt = ldns_pkt_ancount(reply.get());
    for (size_t i = 0; i < cnt; ++i) {
        const auto rr = ldns_rr_list_rr(ldns_pkt_answer(reply.get()), i);
        if (LDNS_RR_TYPE_AAAA != ldns_rr_get_type(rr)) {
            continue;
        }

        const auto rdf = ldns_rr_rdf(rr, 0); // first and only field
        if (!rdf) {
            continue;
        }

        const ag::Uint8View ip6{ldns_rdf_data(rdf), ldns_rdf_size(rdf)};
        if (LDNS_IP6ADDRLEN != ip6.size()) {
            continue;
        }

        auto pref64 = find_pref64(ip6);
        const auto find_result = std::find(result.cbegin(), result.cend(), pref64);
        if (!pref64.empty() && result.cend() == find_result) { // Satisfy uniqueness AND preserve original order
            result.push_back(std::move(pref64));
        }
    }

    return {result, std::nullopt};
}

static bool pref64_valid(const ag::Uint8View pref64) {
    const auto s = pref64.size();
    return ((s >= 4 && s <= 8) || (s == 12 && pref64[IPV6_NULL_IDX] == 0));
}

ag::dns64::ipv6_synth_result ag::dns64::synthesize_ipv4_embedded_ipv6_address(ag::Uint8View prefix, ag::Uint8View ip4) {
    if (!pref64_valid(prefix)) {
        return {{}, "Invalid Pref64::/n"};
    }
    if (ip4.size() != LDNS_IP4ADDRLEN) {
        return {{}, "Invalid IPv4 addr"};
    }

    Uint8Array<LDNS_IP6ADDRLEN> result{};

    std::copy(prefix.cbegin(), prefix.cend(), result.begin());

    size_t ip4_idx = 0;
    for (size_t i = prefix.size(); i < LDNS_IP6ADDRLEN && ip4_idx < LDNS_IP4ADDRLEN; ++i) {
        if (i != IPV6_NULL_IDX) {
            result[i] = ip4[ip4_idx++];
        }
    }

    // Suffix is all zeros
    return {result, std::nullopt};
}
