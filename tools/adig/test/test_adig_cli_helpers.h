// Shared inline helpers for the split adig_cli unit tests.
//
// The pure CLI tests are split across test_adig_cli.cpp (parsing),
// test_adig_cli_edns.cpp (EDNS/IP) and test_adig_cli_packet.cpp
// (packet/formatting), mirroring the source split. The helpers below were
// previously file-local (anonymous-namespace) in the single test file; they
// are `inline` here so each translation unit that includes this header gets a
// non-conflicting definition.
//
// gtest's bundled main() is linked via gtest::gtest, so these sources carry
// only TEST() cases and shared helpers — no explicit main().

#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include <ldns/ldns.h>

#include "adig_cli.h"

namespace ag::adig::test {

// Byte vector alias used by the EDNS/ECS byte-exact tests below.
using Bytes = std::vector<uint8_t>;

// Helper: parse a argv vector and return the result. Keeps the strings alive
// and mutable so `char *` pointers can be handed to parse_args (which takes
// `char *argv[]`, not `const char *`) without a const_cast.
inline ParseResult parse(std::vector<std::string> args) {
    std::vector<std::string> owned = std::move(args);
    std::vector<char *> argv;
    argv.reserve(owned.size());
    for (std::string &a : owned) {
        argv.push_back(a.data());
    }
    return parse_args(static_cast<int>(argv.size()), argv.data());
}

// Build a simple A query for the format_packet_dig tests.
inline ldns_pkt_ptr make_test_query() {
    return make_query("example.com", LDNS_RR_TYPE_A, true);
}

// Check that `haystack` contains `needle`.
inline bool contains(std::string_view haystack, std::string_view needle) {
    return haystack.find(needle) != std::string::npos;
}

// Build a packet whose ADDITIONAL section carries the given RRs (presentation
// strings, e.g. "ns1.example.net. 300 IN A 1.2.3.4"). Each RR is parsed with
// ldns_rr_new_frm_str; a parse failure skips that RR. The packet takes ownership
// of every pushed RR.
inline ldns_pkt_ptr make_glue_pkt(std::vector<std::string> rrs) {
    ldns_pkt_ptr pkt{ldns_pkt_new()};
    for (const std::string &rr_str : rrs) {
        ldns_rr *rr = nullptr;
        if (ldns_rr_new_frm_str(&rr, rr_str.c_str(), 0, nullptr, nullptr) == LDNS_STATUS_OK && rr != nullptr) {
            ldns_pkt_push_rr(pkt.get(), LDNS_SECTION_ADDITIONAL, rr);
        }
    }
    return pkt;
}

// Render `ip` the way ldns renders an A/AAAA RDATA atom, so glue-address
// expectations don't depend on ldns's canonical-form choices.
inline std::string render_ip(ldns_rdf_type type, std::string_view ip) {
    std::unique_ptr<ldns_rdf, void (*)(ldns_rdf *)> rdf(
            ldns_rdf_new_frm_str(type, std::string(ip).c_str()), &ldns_rdf_deep_free);
    if (rdf == nullptr) {
        return "<invalid>";
    }
    // `AllocatedPtr` lives in `ag::` (from common/defs.h, included via adig_cli.h).
    // Qualify it explicitly rather than relying on `ag` being an enclosing
    // namespace of `ag::adig::test`.
    ag::AllocatedPtr<char> s(ldns_rdf2str(rdf.get()));
    return (s != nullptr) ? std::string(s.get()) : "<invalid>";
}

// Count (non-overlapping) occurrences of `needle` in `haystack`.
inline size_t count_of(std::string_view haystack, std::string_view needle) {
    size_t n = 0;
    for (size_t pos = 0;;) {
        pos = haystack.find(needle, pos);
        if (pos == std::string_view::npos) {
            break;
        }
        ++n;
        pos += needle.size();
    }
    return n;
}

// Build a packet whose ANSWER section carries the given presentation RRs.
inline ldns_pkt_ptr make_answer_pkt(std::vector<std::string> rrs) {
    ldns_pkt_ptr pkt{ldns_pkt_new()};
    for (const std::string &rr_str : rrs) {
        ldns_rr *rr = nullptr;
        if (ldns_rr_new_frm_str(&rr, rr_str.c_str(), 0, nullptr, nullptr) == LDNS_STATUS_OK && rr != nullptr) {
            ldns_pkt_push_rr(pkt.get(), LDNS_SECTION_ANSWER, rr);
        }
    }
    return pkt;
}

// Attach EDNS (udp size + version 0) and, when `opt_tlv` is non-empty, the
// given raw EDNS option bytes as edns_data — so the OPT PSEUDOSECTION decoder
// can be exercised without a live server.
inline void attach_edns(ldns_pkt *pkt, uint16_t udp_size, const std::vector<uint8_t> &opt_tlv) {
    ldns_pkt_set_edns_udp_size(pkt, udp_size);
    ldns_pkt_set_edns_version(pkt, 0);
    if (!opt_tlv.empty()) {
        ldns_rdf *rdf = ldns_rdf_new_frm_data(LDNS_RDF_TYPE_NONE, opt_tlv.size(), opt_tlv.data());
        if (rdf != nullptr) {
            ldns_pkt_set_edns_data(pkt, rdf);
        }
    }
}

// Read a packet's raw EDNS option bytes (the edns_data rdf), if any.
inline std::vector<uint8_t> edns_data_bytes(const ldns_pkt *pkt) {
    ldns_rdf *data = ldns_pkt_edns_data(pkt);
    if (data == nullptr) {
        return {};
    }
    const uint8_t *b = ldns_rdf_data(data);
    return {b, b + ldns_rdf_size(data)};
}

} // namespace ag::adig::test
