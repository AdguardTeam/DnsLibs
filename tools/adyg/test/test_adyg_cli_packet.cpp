// Unit tests for adyg's pure CLI layer — packet construction & formatting.
//
// One of the split test translation units registered in
// tools/adyg/CMakeLists.txt. It covers the functions implemented in
// adyg_cli_packet.cpp: make_query, apply_dns_flags, additional_glue /
// glue_address_usable, format_packet_dig / format_trace_packet_dig /
// format_trace_received_line, and format_dig_server / format_dig_when.
// Parsing tests live in test_adyg_cli.cpp and EDNS/IP tests in
// test_adyg_cli_edns.cpp. Shared helpers are in test_adyg_cli_helpers.h.

#include <gtest/gtest.h>

#include <algorithm>
#include <string>
#include <vector>

#include <fmt/format.h>

#include "adyg_cli.h"
#include "test_adyg_cli_helpers.h"

namespace ag::adyg::test {

// --- make_query (query construction is pure) ------------------------------

TEST(MakeQuery, RdBitReflectsRecurse) {
    ldns_pkt_ptr no_rd = make_query("example.com", LDNS_RR_TYPE_A, false);
    ASSERT_NE(nullptr, no_rd.get());
    EXPECT_FALSE(ldns_pkt_rd(no_rd.get()));
    ldns_pkt_ptr with_rd = make_query("example.com", LDNS_RR_TYPE_A, true);
    ASSERT_NE(nullptr, with_rd.get());
    EXPECT_TRUE(ldns_pkt_rd(with_rd.get()));
}

TEST(MakeQuery, AppendsRootLabel) {
    ldns_pkt_ptr q = make_query("example.com", LDNS_RR_TYPE_A, true);
    ASSERT_NE(nullptr, q.get());
    const ldns_rr_list *question = ldns_pkt_question(q.get());
    ASSERT_NE(nullptr, question);
    ASSERT_EQ(1u, ldns_rr_list_rr_count(question));
    AllocatedPtr<char> owner(ldns_rdf2str(ldns_rr_owner(ldns_rr_list_rr(question, 0))));
    ASSERT_NE(nullptr, owner.get());
    EXPECT_TRUE(std::string(owner.get()).ends_with("."));
}

TEST(MakeQuery, InvalidNameReturnsNull) {
    // A label with a stray dot-terminator inside an impossible name; ldns
    // rejects it. (This guards the null-return path callers check.)
    EXPECT_EQ(nullptr, make_query("", LDNS_RR_TYPE_A, true).get());
}

// --- apply_dns_flags -------------------------------------------------------
//
// Covers the EDNS-layer applier: the DO bit (+dnssec), CD (+cdflag), the OPT
// RR (+edns/+noedns with the per-option forcing rule), the UDP payload size
// (+bufsize), the EDNS Z-field (+ednsflags, optionally OR'd with DO), the
// opcode override (applied last) and the EDNS option TLVs (ECS / NSID /
// padding / generic +ednsopt) in dig's build order.

TEST(ApplyDnsFlags, DnssecSetsDoBitAndUdpSize) {
    ldns_pkt_ptr q = make_query("example.com", LDNS_RR_TYPE_A, true);
    ASSERT_NE(nullptr, q.get());
    CliOptions opts;
    opts.dnssec = true;
    apply_dns_flags(q.get(), opts);
    EXPECT_TRUE(ldns_pkt_edns_do(q.get()));
    EXPECT_GE(ldns_pkt_edns_udp_size(q.get()), 4096u);
}

TEST(ApplyDnsFlags, NoDnssecLeavesDoUnset) {
    ldns_pkt_ptr q = make_query("example.com", LDNS_RR_TYPE_A, true);
    ASSERT_NE(nullptr, q.get());
    CliOptions opts; // dnssec == false
    apply_dns_flags(q.get(), opts);
    EXPECT_FALSE(ldns_pkt_edns_do(q.get()));
}

TEST(ApplyDnsFlags, DefaultOptsAttachOptRecord) {
    // Default CliOptions (edns on, version 0, AD on, COOKIE on): a plain adyg
    // query carries an OPT RR with a >=4096 UDP payload size, no DO bit, the AD
    // flag set, and a DNS COOKIE EDNS option — matching `dig`'s defaults.
    ldns_pkt_ptr q = make_query("example.com", LDNS_RR_TYPE_A, true);
    ASSERT_NE(nullptr, q.get());
    CliOptions opts; // edns == true (default), ad == true (default), cookie == true (default)
    apply_dns_flags(q.get(), opts);
    EXPECT_TRUE(ldns_pkt_edns(q.get()));
    EXPECT_GE(ldns_pkt_edns_udp_size(q.get()), 4096u);
    EXPECT_EQ(0u, ldns_pkt_edns_version(q.get()));
    EXPECT_FALSE(ldns_pkt_edns_do(q.get()));
    EXPECT_TRUE(ldns_pkt_ad(q.get())); // AD flag set by default (mirrors dig)
    // COOKIE option (code 0x000A, 8 bytes) is present in EDNS data by default.
    Bytes data = edns_data_bytes(q.get());
    ASSERT_GE(data.size(), 12u); // 4-byte TLV header + 8-byte client cookie
    EXPECT_EQ(0x00, data[0]);
    EXPECT_EQ(0x0A, data[1]);
    EXPECT_EQ(0x00, data[2]);
    EXPECT_EQ(0x08, data[3]); // length = 8
}

TEST(ApplyDnsFlags, NoEdnsSuppressesOptRecord) {
    ldns_pkt_ptr q = make_query("example.com", LDNS_RR_TYPE_A, true);
    ASSERT_NE(nullptr, q.get());
    CliOptions opts;
    opts.edns = false; // +noedns, nothing else
    apply_dns_flags(q.get(), opts);
    EXPECT_FALSE(ldns_pkt_edns(q.get()));
    EXPECT_FALSE(ldns_pkt_edns_do(q.get()));
}

TEST(ApplyDnsFlags, NoEdnsWithDnssecStillAttachesOpt) {
    // `+noedns +dnssec`: the DO bit lives in the OPT record, so EDNS is forced
    // on regardless of +noedns (verified against `dig +noedns +dnssec +qr`).
    ldns_pkt_ptr q = make_query("example.com", LDNS_RR_TYPE_A, true);
    ASSERT_NE(nullptr, q.get());
    CliOptions opts;
    opts.edns = false;
    opts.dnssec = true;
    apply_dns_flags(q.get(), opts);
    EXPECT_TRUE(ldns_pkt_edns(q.get()));
    EXPECT_TRUE(ldns_pkt_edns_do(q.get()));
}

TEST(ApplyDnsFlags, NoEdnsWithSubnetStillAttachesOpt) {
    // `+noedns +subnet`: ECS is an EDNS option, so EDNS is forced on regardless
    // of +noedns (verified against `dig +noedns +subnet=... +qr`).
    ldns_pkt_ptr q = make_query("example.com", LDNS_RR_TYPE_A, true);
    ASSERT_NE(nullptr, q.get());
    CliOptions opts;
    opts.edns = false;
    opts.subnet = {.enabled = true, .addr = "1.2.3.4", .src_prefix = 24};
    opts.cookie = false;
    apply_dns_flags(q.get(), opts);
    EXPECT_TRUE(ldns_pkt_edns(q.get()));
    ldns_rdf *data = ldns_pkt_edns_data(q.get());
    ASSERT_NE(nullptr, data);
    const uint8_t *bytes = ldns_rdf_data(data);
    size_t sz = ldns_rdf_size(data);
    Bytes actual(bytes, bytes + sz);
    EXPECT_EQ((Bytes{0x00, 0x08, 0x00, 0x07, 0x00, 0x01, 0x18, 0x00, 0x01, 0x02, 0x03}), actual);
}

TEST(ApplyDnsFlags, EdnsVersionPropagated) {
    // `+edns=1` advertises EDNS version 1 in the OPT RR.
    ldns_pkt_ptr q = make_query("example.com", LDNS_RR_TYPE_A, true);
    ASSERT_NE(nullptr, q.get());
    CliOptions opts;
    opts.edns_version = 1;
    apply_dns_flags(q.get(), opts);
    EXPECT_TRUE(ldns_pkt_edns(q.get()));
    EXPECT_EQ(1u, ldns_pkt_edns_version(q.get()));
}

TEST(ApplyDnsFlags, NoEdnsWithCdSetsHeaderBitOnly) {
    // CD is a DNS header flag, not an EDNS extension: +noedns +cdflag must set
    // CD without attaching an OPT RR (verified against `dig +noedns +cd +qr`).
    ldns_pkt_ptr q = make_query("example.com", LDNS_RR_TYPE_A, true);
    ASSERT_NE(nullptr, q.get());
    CliOptions opts;
    opts.edns = false;
    opts.cd = true;
    apply_dns_flags(q.get(), opts);
    EXPECT_TRUE(ldns_pkt_cd(q.get()));
    EXPECT_FALSE(ldns_pkt_edns(q.get()));
}

TEST(ApplyDnsFlags, CdSetsCheckingDisabled) {
    ldns_pkt_ptr q = make_query("example.com", LDNS_RR_TYPE_A, true);
    ASSERT_NE(nullptr, q.get());
    CliOptions opts;
    opts.cd = true;
    apply_dns_flags(q.get(), opts);
    EXPECT_TRUE(ldns_pkt_cd(q.get()));
}

TEST(ApplyDnsFlags, CombinedDnssecCdAndNorecurse) {
    // norecurse is handled by make_query (RD bit); dnssec+cd by apply_dns_flags.
    ldns_pkt_ptr q = make_query("example.com", LDNS_RR_TYPE_A, false);
    ASSERT_NE(nullptr, q.get());
    CliOptions opts;
    opts.dnssec = true;
    opts.cd = true;
    apply_dns_flags(q.get(), opts);
    EXPECT_FALSE(ldns_pkt_rd(q.get()));     // norecurse honored
    EXPECT_TRUE(ldns_pkt_edns_do(q.get())); // dnssec DO set
    EXPECT_TRUE(ldns_pkt_cd(q.get()));      // checking disabled set
}

TEST(ApplyDnsFlags, SubnetAttachesEcsOption) {
    ldns_pkt_ptr q = make_query("example.com", LDNS_RR_TYPE_A, true);
    ASSERT_NE(nullptr, q.get());
    CliOptions opts;
    opts.subnet = {.enabled = true, .addr = "1.2.3.4", .src_prefix = 24};
    opts.cookie = false;
    apply_dns_flags(q.get(), opts);
    ldns_rdf *data = ldns_pkt_edns_data(q.get());
    ASSERT_NE(nullptr, data);
    const uint8_t *bytes = ldns_rdf_data(data);
    size_t sz = ldns_rdf_size(data);
    Bytes actual(bytes, bytes + sz);
    EXPECT_EQ((Bytes{0x00, 0x08, 0x00, 0x07, 0x00, 0x01, 0x18, 0x00, 0x01, 0x02, 0x03}), actual);
}

TEST(ApplyDnsFlags, BufsizeOverridesDefaultUdpSize) {
    ldns_pkt_ptr q = make_query("example.com", LDNS_RR_TYPE_A, true);
    ASSERT_NE(nullptr, q.get());
    CliOptions opts;
    opts.edns_bufsize = 512;
    apply_dns_flags(q.get(), opts);
    EXPECT_EQ(512u, ldns_pkt_edns_udp_size(q.get()));
}

TEST(ApplyDnsFlags, NsidAttachesOptionThree) {
    ldns_pkt_ptr q = make_query("example.com", LDNS_RR_TYPE_A, true);
    ASSERT_NE(nullptr, q.get());
    CliOptions opts;
    opts.nsid = true;
    opts.cookie = false;
    apply_dns_flags(q.get(), opts);
    EXPECT_TRUE(ldns_pkt_edns(q.get()));
    EXPECT_EQ((Bytes{0x00, 0x03, 0x00, 0x00}), edns_data_bytes(q.get()));
}

TEST(ApplyDnsFlags, PaddingAttachesOptionTwelve) {
    ldns_pkt_ptr q = make_query("example.com", LDNS_RR_TYPE_A, true);
    ASSERT_NE(nullptr, q.get());
    CliOptions opts;
    opts.padding = 4;
    opts.cookie = false;
    apply_dns_flags(q.get(), opts);
    Bytes expected{0x00, 0x0C, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00};
    EXPECT_EQ(expected, edns_data_bytes(q.get()));
}

TEST(ApplyDnsFlags, CombinedEcsNsidPaddingOptions) {
    // +subnet +nsid +padding concatenate their TLVs into one edns_data blob,
    // in the order ECS(8), NSID(3), Padding(12).
    ldns_pkt_ptr q = make_query("example.com", LDNS_RR_TYPE_A, true);
    ASSERT_NE(nullptr, q.get());
    CliOptions opts;
    opts.subnet = {.enabled = true, .addr = "1.2.3.4", .src_prefix = 24};
    opts.nsid = true;
    opts.padding = 2;
    opts.cookie = false;
    apply_dns_flags(q.get(), opts);
    Bytes expected{};
    auto ecs = encode_ecs_option("1.2.3.4", 24);
    expected.insert(expected.end(), ecs.begin(), ecs.end());
    auto nsid = encode_edns_option(0x03, nullptr, 0);
    expected.insert(expected.end(), nsid.begin(), nsid.end());
    std::vector<uint8_t> zeros(2, 0);
    auto pad = encode_edns_option(0x0C, zeros.data(), zeros.size());
    expected.insert(expected.end(), pad.begin(), pad.end());
    EXPECT_EQ(expected, edns_data_bytes(q.get()));
}

TEST(ApplyDnsFlags, NoEdnsWithNsidStillAttachesOpt) {
    // NSID is an EDNS option, so it forces an OPT RR even under +noedns
    // (mirrors the +dnssec/+subnet cases, verified against `dig +noedns +nsid +qr`).
    ldns_pkt_ptr q = make_query("example.com", LDNS_RR_TYPE_A, true);
    ASSERT_NE(nullptr, q.get());
    CliOptions opts;
    opts.edns = false;
    opts.nsid = true;
    opts.cookie = false;
    apply_dns_flags(q.get(), opts);
    EXPECT_TRUE(ldns_pkt_edns(q.get()));
    EXPECT_EQ((Bytes{0x00, 0x03, 0x00, 0x00}), edns_data_bytes(q.get()));
}

TEST(ApplyDnsFlags, EdnsFlagsSetsZField) {
    ldns_pkt_ptr q = make_query("example.com", LDNS_RR_TYPE_A, true);
    ASSERT_NE(nullptr, q.get());
    CliOptions opts;
    opts.edns_flags = 0x0080;
    apply_dns_flags(q.get(), opts);
    EXPECT_EQ(0x0080u, ldns_pkt_edns_z(q.get()));
}

TEST(ApplyDnsFlags, EdnsFlagsOrDnssecDoBit) {
    // +ednsflags=0x80 +dnssec: the DO bit (0x8000) ORs into the Z field.
    ldns_pkt_ptr q = make_query("example.com", LDNS_RR_TYPE_A, true);
    ASSERT_NE(nullptr, q.get());
    CliOptions opts;
    opts.dnssec = true;
    opts.edns_flags = 0x0080;
    apply_dns_flags(q.get(), opts);
    EXPECT_EQ(0x8080u, ldns_pkt_edns_z(q.get()));
}

TEST(ApplyDnsFlags, OpcodeAppliedLast) {
    ldns_pkt_ptr q = make_query("example.com", LDNS_RR_TYPE_A, true);
    ASSERT_NE(nullptr, q.get());
    CliOptions opts;
    opts.opcode = LDNS_PACKET_NOTIFY;
    apply_dns_flags(q.get(), opts);
    EXPECT_EQ(LDNS_PACKET_NOTIFY, ldns_pkt_get_opcode(q.get()));
}

TEST(ApplyDnsFlags, OpcodeUnderNoEdnsNoOpt) {
    // +noedns +opcode=NOTIFY: the opcode override still applies, no OPT RR.
    ldns_pkt_ptr q = make_query("example.com", LDNS_RR_TYPE_A, true);
    ASSERT_NE(nullptr, q.get());
    CliOptions opts;
    opts.edns = false;
    opts.opcode = LDNS_PACKET_NOTIFY;
    apply_dns_flags(q.get(), opts);
    EXPECT_EQ(LDNS_PACKET_NOTIFY, ldns_pkt_get_opcode(q.get()));
    EXPECT_FALSE(ldns_pkt_edns(q.get()));
}

TEST(ApplyDnsFlags, OpcodeSurvivesWireSerialization) {
    // Regression: `+opcode=STATUS` must reach the wire, not just the in-memory
    // packet. The opcode lives in the DNS header (bits 11..14 of word 2); after
    // make_query + apply_dns_flags the serialized packet must carry it (the
    // upstream plain/DNSCrypt exchange serializes via ldns_pkt2buffer_wire, so a
    // set-but-unserializable opcode would silently go out as QUERY).
    ldns_pkt_ptr q = make_query("example.com", LDNS_RR_TYPE_A, true);
    ASSERT_NE(nullptr, q.get());
    CliOptions opts;
    opts.opcode = LDNS_PACKET_STATUS;
    apply_dns_flags(q.get(), opts);
    ASSERT_EQ(LDNS_PACKET_STATUS, ldns_pkt_get_opcode(q.get()));
    uint8_t *wire = nullptr;
    size_t sz = 0;
    ASSERT_EQ(LDNS_STATUS_OK, ldns_pkt2wire(&wire, q.get(), &sz));
    ag::AllocatedPtr<uint8_t> owned(wire);
    ASSERT_GE(sz, 4u);
    uint16_t flags = static_cast<uint16_t>((wire[2] << 8) | wire[3]);
    uint16_t opcode_field = (flags >> 11) & 0x0F;
    EXPECT_EQ(static_cast<uint16_t>(LDNS_PACKET_STATUS), opcode_field);
}

TEST(ApplyDnsFlags, EdnsoptAttachesOptionTlv) {
    // `+ednsopt=3` attaches an NSID option (code 3, empty data) and forces an
    // OPT RR (an EDNS option always lives inside the OPT record).
    ldns_pkt_ptr q = make_query("example.com", LDNS_RR_TYPE_A, true);
    ASSERT_NE(nullptr, q.get());
    CliOptions opts;
    opts.ednsopts.push_back({.code = 3, .data = {}});
    opts.cookie = false;
    apply_dns_flags(q.get(), opts);
    EXPECT_TRUE(ldns_pkt_edns(q.get()));
    EXPECT_EQ((Bytes{0x00, 0x03, 0x00, 0x00}), edns_data_bytes(q.get()));
}

TEST(ApplyDnsFlags, EdnsoptWithPayload) {
    ldns_pkt_ptr q = make_query("example.com", LDNS_RR_TYPE_A, true);
    ASSERT_NE(nullptr, q.get());
    CliOptions opts;
    opts.ednsopts.push_back({.code = 12, .data = Bytes{0x04, 0x08}});
    opts.cookie = false;
    apply_dns_flags(q.get(), opts);
    EXPECT_EQ((Bytes{0x00, 0x0C, 0x00, 0x02, 0x04, 0x08}), edns_data_bytes(q.get()));
}

TEST(ApplyDnsFlags, NoEdnsWithEdnsoptStillAttachesOpt) {
    // A generic EDNS option forces an OPT RR even under `+noedns`, mirroring
    // adyg's `+nsid` / `+subnet` / `+padding` / `+ednsflags` policy (each lives
    // inside the OPT record). dig itself only attaches it when EDNS is enabled;
    // adyg attaches it unconditionally for consistency.
    ldns_pkt_ptr q = make_query("example.com", LDNS_RR_TYPE_A, true);
    ASSERT_NE(nullptr, q.get());
    CliOptions opts;
    opts.edns = false;
    opts.ednsopts.push_back({.code = 3, .data = {}});
    opts.cookie = false;
    apply_dns_flags(q.get(), opts);
    EXPECT_TRUE(ldns_pkt_edns(q.get()));
    EXPECT_EQ((Bytes{0x00, 0x03, 0x00, 0x00}), edns_data_bytes(q.get()));
}

TEST(ApplyDnsFlags, EdnsoptOrderedAfterNamedBeforePadding) {
    // `+subnet +nsid +ednsopt=100:abcd +padding=2` concatenates TLVs in the
    // order ECS(8), NSID(3), ednsopt(100), Padding(12) — mirroring dig's build
    // order (named options, then +ednsopt list, then padding last).
    ldns_pkt_ptr q = make_query("example.com", LDNS_RR_TYPE_A, true);
    ASSERT_NE(nullptr, q.get());
    CliOptions opts;
    opts.subnet = {.enabled = true, .addr = "1.2.3.4", .src_prefix = 24};
    opts.nsid = true;
    opts.ednsopts.push_back({.code = 100, .data = Bytes{0xab, 0xcd}});
    opts.padding = 2;
    opts.cookie = false;
    apply_dns_flags(q.get(), opts);
    Bytes expected{};
    auto ecs = encode_ecs_option("1.2.3.4", 24);
    expected.insert(expected.end(), ecs.begin(), ecs.end());
    auto nsid = encode_edns_option(0x03, nullptr, 0);
    expected.insert(expected.end(), nsid.begin(), nsid.end());
    auto generic = encode_edns_option(100, Bytes{0xab, 0xcd}.data(), 2);
    expected.insert(expected.end(), generic.begin(), generic.end());
    std::vector<uint8_t> zeros(2, 0);
    auto pad = encode_edns_option(0x0C, zeros.data(), zeros.size());
    expected.insert(expected.end(), pad.begin(), pad.end());
    EXPECT_EQ(expected, edns_data_bytes(q.get()));
}

TEST(ApplyDnsFlags, MultipleEdnsoptsPreserveArgvOrder) {
    ldns_pkt_ptr q = make_query("example.com", LDNS_RR_TYPE_A, true);
    ASSERT_NE(nullptr, q.get());
    CliOptions opts;
    opts.ednsopts.push_back({.code = 100, .data = {}});
    opts.ednsopts.push_back({.code = 5, .data = Bytes{0x11}});
    opts.cookie = false;
    apply_dns_flags(q.get(), opts);
    Bytes expected{};
    auto a = encode_edns_option(100, nullptr, 0);
    expected.insert(expected.end(), a.begin(), a.end());
    auto b = encode_edns_option(5, Bytes{0x11}.data(), 1);
    expected.insert(expected.end(), b.begin(), b.end());
    EXPECT_EQ(expected, edns_data_bytes(q.get()));
}

TEST(ApplyDnsFlags, NoAdFlagClearsAd) {
    // `+noadflag` clears the AD flag. AD is a header bit (not EDNS), so it is
    // set/cleared independently of the OPT RR.
    ldns_pkt_ptr q = make_query("example.com", LDNS_RR_TYPE_A, true);
    ASSERT_NE(nullptr, q.get());
    CliOptions opts;
    opts.ad = false;
    opts.cookie = false;
    apply_dns_flags(q.get(), opts);
    EXPECT_FALSE(ldns_pkt_ad(q.get()));
}

TEST(ApplyDnsFlags, AdFlagSetEvenUnderNoEdns) {
    // AD is a DNS header flag, so it is set even under `+noedns` (which
    // suppresses only the OPT RR). Mirrors `dig +noedns +adflag`.
    ldns_pkt_ptr q = make_query("example.com", LDNS_RR_TYPE_A, true);
    ASSERT_NE(nullptr, q.get());
    CliOptions opts;
    opts.edns = false;
    apply_dns_flags(q.get(), opts);
    EXPECT_TRUE(ldns_pkt_ad(q.get())); // AD is a header flag, not EDNS
    EXPECT_FALSE(ldns_pkt_edns(q.get()));
}

TEST(ApplyDnsFlags, NoCookieSuppressesCookieOption) {
    // `+nocookie` suppresses the COOKIE EDNS option; the rest of the OPT RR is
    // unaffected (verified against `dig +nocookie +qr`).
    ldns_pkt_ptr q = make_query("example.com", LDNS_RR_TYPE_A, true);
    ASSERT_NE(nullptr, q.get());
    CliOptions opts;
    opts.nsid = true;
    opts.cookie = false;
    apply_dns_flags(q.get(), opts);
    // With cookie suppressed, EDNS data carries only the NSID option.
    EXPECT_EQ((Bytes{0x00, 0x03, 0x00, 0x00}), edns_data_bytes(q.get()));
}

TEST(ApplyDnsFlags, NoEdnsSuppressesCookie) {
    // COOKIE is an EDNS option, so `+noedns` suppresses it along with the OPT
    // RR. AD (a header flag) is still set. Mirrors `dig +noedns`.
    ldns_pkt_ptr q = make_query("example.com", LDNS_RR_TYPE_A, true);
    ASSERT_NE(nullptr, q.get());
    CliOptions opts;
    opts.edns = false;
    apply_dns_flags(q.get(), opts);
    EXPECT_FALSE(ldns_pkt_edns(q.get()));
    EXPECT_TRUE(ldns_pkt_ad(q.get()));
}

// --- validate_edns_option_sizes -------------------------------------------
//
// The OPT record's RDLEN is a 16-bit field, so the concatenated EDNS option blob
// may not exceed 65535 bytes; each option's option-length is likewise 16-bit, so
// a single option's data may not exceed 65535 bytes (encode_edns_option would
// otherwise truncate it to uint16_t). validate_edns_option_sizes mirrors
// apply_dns_flags's assembly to catch an oversized request up front. The byte
// arithmetic below is worked out from the TLV layout (4-byte header + data):
//   cookie = 4 + 8 = 12, NSID = 4 + 0 = 4, ECS 1.2.3.4/24 = 4 + 4 + 3 = 11.

TEST(ValidateEdnsOptionSizes, EmptyWhenNoOptRecord) {
    // +noedns with no EDNS-bearing option -> no OPT RR -> nothing to validate.
    CliOptions opts;
    opts.edns = false;
    opts.cookie = false;
    EXPECT_TRUE(validate_edns_option_sizes(opts).empty());
}

TEST(ValidateEdnsOptionSizes, DefaultsAreSafe) {
    // Default opts carry only the 8-byte client cookie (12 bytes on the wire).
    CliOptions opts; // edns=true, cookie=true by default
    EXPECT_TRUE(validate_edns_option_sizes(opts).empty());
}

TEST(ValidateEdnsOptionSizes, PaddingFitsAloneAtLimit) {
    // +nocookie +padding=65531 -> 4 + 65531 = 65535 (exactly the RDLEN max).
    CliOptions opts;
    opts.cookie = false;
    opts.padding = 65531;
    EXPECT_TRUE(validate_edns_option_sizes(opts).empty());
}

TEST(ValidateEdnsOptionSizes, PaddingAloneOverLimitRejected) {
    // 4 + 65532 = 65536 > 65535 -> combined overflow (cookie off).
    CliOptions opts;
    opts.cookie = false;
    opts.padding = 65532;
    std::string e = validate_edns_option_sizes(opts);
    EXPECT_FALSE(e.empty());
    EXPECT_NE(std::string::npos, e.find("combined"));
    EXPECT_NE(std::string::npos, e.find("exceeds 65535"));
}

TEST(ValidateEdnsOptionSizes, PaddingMaxValueRejected) {
    // +padding=65535 (the parse-time uint16 cap) alone is 65539 bytes on the
    // wire -> combined overflow even with the cookie suppressed.
    CliOptions opts;
    opts.cookie = false;
    opts.padding = 65535;
    EXPECT_FALSE(validate_edns_option_sizes(opts).empty());
}

TEST(ValidateEdnsOptionSizes, CookiePlusPaddingRejected) {
    // The exact case from the review: the default +cookie (12) plus
    // +padding=65535 (65539) = 65551 > 65535 -> a malformed OPT RDLEN.
    CliOptions opts; // cookie=true by default
    opts.padding = 65535;
    std::string e = validate_edns_option_sizes(opts);
    EXPECT_FALSE(e.empty());
    EXPECT_NE(std::string::npos, e.find("combined"));
    EXPECT_NE(std::string::npos, e.find("65551")); // 12 + 65539
}

TEST(ValidateEdnsOptionSizes, CookiePlusPaddingAtLimit) {
    // 12 + (4 + 65519) = 65535 -> the largest padding that still fits with the
    // default cookie.
    CliOptions opts; // cookie=true by default
    opts.padding = 65519;
    EXPECT_TRUE(validate_edns_option_sizes(opts).empty());
}

TEST(ValidateEdnsOptionSizes, EdnsoptPayloadFitsAtOptionLimit) {
    // A single option carrying 65531 data bytes -> 4 + 65531 = 65535 (OK).
    CliOptions opts;
    opts.cookie = false;
    opts.ednsopts.push_back({.code = 100, .data = Bytes(65531, 0xAA)});
    EXPECT_TRUE(validate_edns_option_sizes(opts).empty());
}

TEST(ValidateEdnsOptionSizes, EdnsoptPayloadExceedsOptionLimit) {
    // A single option carrying > 65535 data bytes would have its option-length
    // truncated to uint16_t by encode_edns_option -> rejected per-option.
    CliOptions opts;
    opts.cookie = false;
    opts.ednsopts.push_back({.code = 100, .data = Bytes(65536, 0xAA)});
    std::string e = validate_edns_option_sizes(opts);
    EXPECT_FALSE(e.empty());
    EXPECT_NE(std::string::npos, e.find("payload"));
    EXPECT_NE(std::string::npos, e.find("exceeds 65535"));
    EXPECT_NE(std::string::npos, e.find("65536"));
}

TEST(ValidateEdnsOptionSizes, MultipleEdnsoptsExceedCombined) {
    // Two 33000-byte options each fit the per-option limit (33000 <= 65535) but
    // together exceed the combined RDLEN: 2 * (4 + 33000) = 66008 > 65535.
    CliOptions opts;
    opts.cookie = false;
    opts.ednsopts.push_back({.code = 100, .data = Bytes(33000, 0x01)});
    opts.ednsopts.push_back({.code = 101, .data = Bytes(33000, 0x02)});
    std::string e = validate_edns_option_sizes(opts);
    EXPECT_FALSE(e.empty());
    EXPECT_NE(std::string::npos, e.find("combined"));
    EXPECT_NE(std::string::npos, e.find("66008"));
}

TEST(ValidateEdnsOptionSizes, EcsCountedAgainstCombined) {
    // ECS 1.2.3.4/24 = 11 bytes; + 4 + 65521 = 65536 > 65535 -> overflow, but
    // with padding one byte smaller (65520) it fits exactly (65535).
    CliOptions opts;
    opts.cookie = false;
    opts.subnet = {.enabled = true, .addr = "1.2.3.4", .src_prefix = 24};
    opts.padding = 65521;
    EXPECT_FALSE(validate_edns_option_sizes(opts).empty());
    opts.padding = 65520; // 11 + (4 + 65520) = 65535
    EXPECT_TRUE(validate_edns_option_sizes(opts).empty());
}

TEST(ValidateEdnsOptionSizes, ForcingOptionKeepsCookieCounted) {
    // Under `+noedns` a forcing option (+padding) still attaches an OPT RR, so
    // the default cookie is still counted: 12 + 65539 = 65551 > 65535.
    CliOptions opts;
    opts.edns = false;    // +noedns
    opts.cookie = true;   // still on by default
    opts.padding = 65535; // forces an OPT RR
    EXPECT_FALSE(validate_edns_option_sizes(opts).empty());
}

TEST(ValidateEdnsOptionSizes, HeaderFieldsNotCounted) {
    // DO/Z-field bits and the UDP payload size live in the OPT RR header, not in
    // the RDATA blob, so they contribute zero bytes here.
    CliOptions opts;
    opts.cookie = false;
    opts.dnssec = true;       // DO bit (header)
    opts.edns_flags = 0x8000; // raw Z bits (header)
    opts.edns_bufsize = 4096; // UDP payload size (header)
    EXPECT_TRUE(validate_edns_option_sizes(opts).empty());
}

TEST(ValidateEdnsOptionSizes, NsidAccounted) {
    // +nocookie +nsid -> 4 bytes (within the limit).
    CliOptions opts;
    opts.cookie = false;
    opts.nsid = true;
    EXPECT_TRUE(validate_edns_option_sizes(opts).empty());
}

// --- make_query (transaction ID seeded) -------------------------------------

TEST(MakeQuery, TransactionIdVariesAfterSeeding) {
    // ldns_get_random() (used by ldns_pkt_set_random_id via ldns_init_random)
    // falls back to POSIX random() when HAVE_SSL is undefined (this ldns build).
    // Without ldns_init_random(), random() defaults to seed 1 and the first call
    // always produces the same 16-bit truncation (0x4567 = 17767) — a classic
    // cache-poisoning vulnerability (CVE-2008-1447). main() calls
    // ldns_init_random(nullptr, 0) to seed from /dev/urandom; this test verifies
    // that after seeding, multiple queries produce distinct transaction IDs.
    ASSERT_EQ(0, ldns_init_random(nullptr, 0));
    std::vector<uint16_t> ids;
    for (int i = 0; i < 10; ++i) {
        ldns_pkt_ptr q = make_query("example.com", LDNS_RR_TYPE_A, true);
        ASSERT_NE(nullptr, q.get());
        ids.push_back(ldns_pkt_id(q.get()));
    }
    std::sort(ids.begin(), ids.end());
    ids.erase(std::unique(ids.begin(), ids.end()), ids.end());
    EXPECT_GT(ids.size(), 1u) << "All transaction IDs identical — PRNG not seeded?";
}

// --- format_packet_dig (dig-style output) --------------------------------

TEST(FormatPacketDig, UsesStatusCodeInsteadOfRcode) {
    ldns_pkt_ptr q = make_test_query();
    std::string out = format_packet_dig(q.get(), {}, false, Millis{0}, "");
    EXPECT_TRUE(contains(out, "status: NOERROR"));
    EXPECT_FALSE(contains(out, "rcode:"));
}

TEST(FormatPacketDig, HasFlagLine) {
    ldns_pkt_ptr q = make_test_query();
    std::string out = format_packet_dig(q.get(), {}, false, Millis{0}, "");
    // RD is set by make_query(..., recurse=true)
    EXPECT_TRUE(contains(out, "flags:"));
    EXPECT_TRUE(contains(out, " rd"));
    EXPECT_TRUE(contains(out, "QUERY: 1"));
}

TEST(FormatPacketDig, QuerySaysSending) {
    ldns_pkt_ptr q = make_test_query();
    std::string out = format_packet_dig(q.get(), {}, true, Millis{0}, "");
    EXPECT_TRUE(contains(out, ";; Sending:"));
    // dig's +qr query echo prints `;; QUERY SIZE: N` (not `;; MSG SIZE  sent:`).
    EXPECT_TRUE(contains(out, ";; QUERY SIZE:"));
}

TEST(FormatPacketDig, QueryEchoOmitsQueryTimeAndServer) {
    // `+qr` echoes the query packet before it is sent: there is no round-trip
    // yet, so the stats trailer must omit the ";; Query time:" line (and, since
    // the caller passes an empty server for the echo, the ";; SERVER:" line
    // too), leaving only ";; QUERY SIZE:". Mirrors `dig +qr`, which prints
    // just the query size for the query packet. Previously a spurious
    // ";; Query time: 0 msec" was emitted here. dig's +qr uses the label
    // "QUERY SIZE:" (not "MSG SIZE  sent:").
    ldns_pkt_ptr q = make_test_query();
    std::string out = format_packet_dig(q.get(), {}, true, Millis{0}, "");
    EXPECT_TRUE(contains(out, ";; QUERY SIZE:"));
    EXPECT_FALSE(contains(out, "Query time:"));
    EXPECT_FALSE(contains(out, "SERVER:"));
    EXPECT_FALSE(contains(out, "MSG SIZE"));
}

TEST(FormatPacketDig, ResponseSaysGotAnswer) {
    ldns_pkt_ptr q = make_test_query();
    std::string out = format_packet_dig(q.get(), {}, false, Millis{0}, "");
    EXPECT_TRUE(contains(out, ";; Got answer:"));
    EXPECT_TRUE(contains(out, "MSG SIZE  rcvd:"));
}

TEST(FormatPacketDig, QuestionSectionHasSemicolonPrefix) {
    ldns_pkt_ptr q = make_test_query();
    std::string out = format_packet_dig(q.get(), {}, false, Millis{0}, "");
    EXPECT_TRUE(contains(out, ";; QUESTION SECTION:"));
    // dig's default QUESTION RR has the owner tab-padded past the (empty) TTL
    // column to col 32 where class IN sits. For a 12-char owner like
    // "example.com." that is 3 tabs.
    EXPECT_TRUE(contains(out, ";example.com.\t\t\tIN\tA"));
}

TEST(FormatPacketDig, NoQuestionSuppressed) {
    ldns_pkt_ptr q = make_test_query();
    DisplayFlags df;
    df.question = false;
    std::string out = format_packet_dig(q.get(), df, false, Millis{0}, "");
    EXPECT_FALSE(contains(out, "QUESTION SECTION"));
}

TEST(FormatPacketDig, NoCommentsSuppressesHeader) {
    ldns_pkt_ptr q = make_test_query();
    DisplayFlags df;
    df.comments = false;
    std::string out = format_packet_dig(q.get(), df, false, Millis{0}, "");
    EXPECT_FALSE(contains(out, "HEADER"));
    EXPECT_FALSE(contains(out, "Got answer:"));
    // Section headers are themselves comments; with +nocomments dig (and now
    // adyg) emits just the RRs without the `;; ... SECTION:` headers.
    EXPECT_FALSE(contains(out, "QUESTION SECTION:"));
    EXPECT_FALSE(contains(out, "ANSWER SECTION:"));
    // The question RR is still present (gated by +question, not +comments).
    EXPECT_TRUE(contains(out, ";example.com.\t\t\tIN\tA"));
}

TEST(FormatPacketDig, NoStatsSuppressesStats) {
    ldns_pkt_ptr q = make_test_query();
    DisplayFlags df;
    df.stats = false;
    std::string out = format_packet_dig(q.get(), df, false, Millis{0}, "");
    EXPECT_FALSE(contains(out, "Query time:"));
    EXPECT_FALSE(contains(out, "MSG SIZE"));
}

TEST(FormatPacketDig, NoAllSuppressesEverything) {
    ldns_pkt_ptr q = make_test_query();
    DisplayFlags df;
    df.cmd = false;
    df.comments = false;
    df.question = false;
    df.answer = false;
    df.authority = false;
    df.additional = false;
    df.stats = false;
    df.multiline = false;
    df.ttlid = false;
    df.cls = false;
    std::string out = format_packet_dig(q.get(), df, false, Millis{0}, "");
    EXPECT_TRUE(out.empty());
}

TEST(FormatPacketDig, EdnsOptPseudosectionWhenDnssec) {
    ldns_pkt_ptr q = make_test_query();
    CliOptions opts;
    opts.dnssec = true;
    apply_dns_flags(q.get(), opts);
    std::string out = format_packet_dig(q.get(), {}, false, Millis{0}, "");
    EXPECT_TRUE(contains(out, "OPT PSEUDOSECTION:"));
    EXPECT_TRUE(contains(out, "; EDNS: version: 0"));
    EXPECT_TRUE(contains(out, "flags: do"));
    EXPECT_TRUE(contains(out, "udp: 4096"));
    // ADDITIONAL count should include the OPT RR
    EXPECT_TRUE(contains(out, "ADDITIONAL: 1"));
}

TEST(FormatPacketDig, NoEdnsNoPseudosection) {
    ldns_pkt_ptr q = make_test_query();
    std::string out = format_packet_dig(q.get(), {}, false, Millis{0}, "");
    EXPECT_FALSE(contains(out, "OPT PSEUDOSECTION:"));
    EXPECT_TRUE(contains(out, "ADDITIONAL: 0"));
}

// --- bug #6: OPT PSEUDOSECTION appears with +comments alone -----------------

TEST(FormatPacketDig, OptPseudosectionWithCommentsOnlyNoAdditional) {
    // dig 9.20 verified: `dig +noall +comments` (additional OFF) still prints
    // the OPT PSEUDOSECTION. The historic adyg code gated it on both
    // `+comments AND +additional`, suppressing it (wrongly) when +additional
    // was off. Now OPT PSEUDOSECTION is gated solely on +comments.
    ldns_pkt_ptr q = make_test_query();
    CliOptions opts;
    opts.dnssec = true;
    apply_dns_flags(q.get(), opts);
    DisplayFlags df;
    df.cmd = false;
    df.comments = true;
    df.question = false;
    df.answer = false;
    df.authority = false;
    df.additional = false; // trace-default-style: +additional OFF
    df.stats = false;
    std::string out = format_packet_dig(q.get(), df, false, Millis{0}, "");
    EXPECT_TRUE(contains(out, "OPT PSEUDOSECTION:"));
    EXPECT_TRUE(contains(out, "; EDNS: version: 0"));
    EXPECT_TRUE(contains(out, "flags: do"));
    // No ADDITIONAL-section RRs (just OPT, shown in PSEUDOSECTION).
    EXPECT_FALSE(contains(out, "ANSWER SECTION"));
    EXPECT_FALSE(contains(out, "ADDITIONAL SECTION"));
}

TEST(FormatPacketDig, NoCommentsSuppressesOptPseudosection) {
    // When +nocomments is on, the OPT PSEUDOSECTION (which is itself a
    // comment block) is suppressed — verified against `dig +nocomments`.
    ldns_pkt_ptr q = make_test_query();
    CliOptions opts;
    opts.dnssec = true;
    apply_dns_flags(q.get(), opts);
    DisplayFlags df;
    df.cmd = false;
    df.comments = false;
    df.question = false;
    df.answer = false;
    df.authority = false;
    df.additional = true;
    df.stats = false;
    std::string out = format_packet_dig(q.get(), df, false, Millis{0}, "");
    EXPECT_FALSE(contains(out, "OPT PSEUDOSECTION:"));
    EXPECT_FALSE(contains(out, "EDNS:"));
}

TEST(FormatPacketDig, QueryTimeInStats) {
    ldns_pkt_ptr q = make_test_query();
    std::string out = format_packet_dig(q.get(), {}, false, Millis{42}, "");
    EXPECT_TRUE(contains(out, ";; Query time: 42 msec"));
}

TEST(FormatPacketDig, ServerLineWhenProvided) {
    ldns_pkt_ptr q = make_test_query();
    std::string out = format_packet_dig(q.get(), {}, false, Millis{0}, "1.1.1.1");
    EXPECT_TRUE(contains(out, ";; SERVER: 1.1.1.1"));
}

TEST(FormatPacketDig, NoServerLineWhenEmpty) {
    ldns_pkt_ptr q = make_test_query();
    std::string out = format_packet_dig(q.get(), {}, false, Millis{0}, "");
    EXPECT_FALSE(contains(out, "SERVER:"));
}

TEST(FormatPacketDig, NoTtlidOmitsTtl) {
    ldns_pkt_ptr q = make_test_query();
    DisplayFlags df;
    df.ttlid = false;
    std::string out = format_packet_dig(q.get(), df, false, Millis{0}, "");
    // Question section never has TTL, so just verify the flag doesn't crash
    // and the question section still appears.
    EXPECT_TRUE(contains(out, "QUESTION SECTION"));
}

TEST(FormatPacketDig, EdnsoptNsidPayloadDecoded) {
    // A `+ednsopt=3:414243` query echo decodes as an NSID option in the OPT
    // PSEUDOSECTION (code 3 is NSID), rendering `; NSID: <hex> ("<ascii>")`.
    ldns_pkt_ptr q = make_query("example.com", LDNS_RR_TYPE_A, true);
    ASSERT_NE(nullptr, q.get());
    CliOptions opts;
    opts.ednsopts.push_back({.code = 3, .data = Bytes{'A', 'B', 'C'}});
    apply_dns_flags(q.get(), opts);
    std::string out = format_packet_dig(q.get(), {}, false, Millis{0}, "");
    EXPECT_TRUE(contains(out, "; NSID: 414243 (\"ABC\")"));
}

TEST(FormatPacketDig, EdnsoptUnknownCodeGenericHex) {
    // An unassigned option code falls back to dig's generic `; \# N <hex>` form.
    ldns_pkt_ptr q = make_query("example.com", LDNS_RR_TYPE_A, true);
    ASSERT_NE(nullptr, q.get());
    CliOptions opts;
    opts.ednsopts.push_back({.code = 100, .data = Bytes{0xab, 0xcd}});
    apply_dns_flags(q.get(), opts);
    std::string out = format_packet_dig(q.get(), {}, false, Millis{0}, "");
    EXPECT_TRUE(contains(out, "; \\# 2 abcd"));
}

TEST(FormatPacketDig, TtlUnitsAppliedToAnswer) {
    ldns_pkt_ptr pkt = make_answer_pkt({"example.com. 300 IN A 1.2.3.4"});
    DisplayFlags df;
    df.cmd = false;
    df.comments = false;
    df.question = false;
    df.answer = true;
    df.authority = false;
    df.additional = false;
    df.stats = false;
    df.ttl_units = true;
    std::string out = format_packet_dig(pkt.get(), df, false, Millis{0}, "");
    EXPECT_TRUE(contains(out, "\t5m\tIN\tA\t1.2.3.4"));
}

// --- bug #1: +noclass keeps IN in QUESTION ---------------------------------

TEST(FormatPacketDig, NoClassKeepsClassInQuestion) {
    // `dig +noclass` still prints `IN` in QUESTION lines; only the
    // answer/authority/additional sections drop the class. With +noclass the
    // QUESTION's class IN moves to col 24 (one column left of the default,
    // since the TTL column is no longer preserved when flags.ttlid is no
    // longer in effect for the +noclass style).
    ldns_pkt_ptr q = make_test_query();
    DisplayFlags df;
    df.cls = false;
    std::string out = format_packet_dig(q.get(), df, false, Millis{0}, "");
    EXPECT_TRUE(contains(out, ";example.com.\t\tIN\tA"));
}

TEST(FormatPacketDig, NoClassDropsClassInAnswer) {
    ldns_pkt_ptr pkt = make_answer_pkt({"example.com. 300 IN A 1.2.3.4"});
    DisplayFlags df;
    df.cls = false;
    df.cmd = false;
    df.comments = false;
    df.question = false;
    df.answer = true;
    df.authority = false;
    df.additional = false;
    df.stats = false;
    std::string out = format_packet_dig(pkt.get(), df, false, Millis{0}, "");
    // The 12-char owner "example.com." pads to col 24 with 2 tabs (dig's
    // master-file column layout for +noclass: ttl_col=24, type_col=32,
    // rdata_col=40).
    EXPECT_TRUE(contains(out, "example.com.\t\t300\tA\t1.2.3.4"));
    EXPECT_FALSE(contains(out, "\tIN\t"));
}

// --- bug #8: column layout byte-exact (mirrors dig's master_file_style) -------

TEST(FormatPacketDig, DefaultColumnLayoutByteExact) {
    // dig 9.20 default single-line: `owner<pad to col 24>TTL\tCLASS\tTYPE\tRDATA`
    // — the 7-char owner "a.test." needs 3 tabs to reach col 24; RDATA is
    // space-separated within itself (for multi-RDATA types like SOA).
    ldns_pkt_ptr pkt = make_answer_pkt({
            "a.test. 300 IN A 1.2.3.4",
            "soa.test. 300 IN SOA ns1.test. admin.test. 1 7200 3600 604800 86400",
    });
    DisplayFlags df;
    df.cmd = false;
    df.comments = false;
    df.question = false;
    df.answer = true;
    df.authority = false;
    df.additional = false;
    df.stats = false;
    std::string out = format_packet_dig(pkt.get(), df, false, Millis{0}, "");
    // First RR: 3 tabs from a 7-char owner to col 24, then tab-separated
    // columns and RDATA byte-exact.
    EXPECT_EQ("a.test.\t\t\t300\tIN\tA\t1.2.3.4\n", out.substr(0, 27));
    // Second RR: 9-char owner takes 2 tabs (col 24); SOA's multi-RDATA
    // (mname, rname, serial, refresh, retry, expire, minimum) is joined with
    // single spaces.
    EXPECT_TRUE(contains(out, "soa.test.\t\t300\tIN\tSOA\tns1.test. admin.test. 1 7200 3600 604800 86400\n"));
}

TEST(FormatPacketDig, NottlidShiftsColumnsLeft) {
    // dig 9.20 +nottlid single-line: owner padded to col 24, then CLASS
    // shifts to the TTL column (col 24), TYPE to col 32, RDATA to col 40.
    ldns_pkt_ptr pkt = make_answer_pkt({"a.test. 300 IN A 1.2.3.4"});
    DisplayFlags df;
    df.cmd = false;
    df.comments = false;
    df.question = false;
    df.answer = true;
    df.authority = false;
    df.additional = false;
    df.stats = false;
    df.ttlid = false;
    std::string out = format_packet_dig(pkt.get(), df, false, Millis{0}, "");
    // 3 tabs (7-char owner → 8 → 16 → 24); then IN at col 24, A at col 32.
    EXPECT_EQ("a.test.\t\t\tIN\tA\t1.2.3.4\n", out);
}

TEST(FormatPacketDig, NottlidNoclassTypeAtTtlColumn) {
    // dig verified: `+nottlid +noclass` puts TYPE directly at the owner
    // column (col 24), RDATA at col 32.
    ldns_pkt_ptr pkt = make_answer_pkt({"a.test. 300 IN A 1.2.3.4"});
    DisplayFlags df;
    df.cmd = false;
    df.comments = false;
    df.question = false;
    df.answer = true;
    df.authority = false;
    df.additional = false;
    df.stats = false;
    df.ttlid = false;
    df.cls = false;
    std::string out = format_packet_dig(pkt.get(), df, false, Millis{0}, "");
    EXPECT_EQ("a.test.\t\t\tA\t1.2.3.4\n", out);
}

TEST(FormatPacketDig, QuestionDefaultKeepsEmptyTtlColumn) {
    // dig verified: default QUESTION section preserves the empty TTL column
    // (the owner gets one extra tab stop to col 32 so the class IN sits in
    // the same column as in the RR-data sections). Mirrors dig's
    // `;a.test.\t\t\t\tIN\tA` (4 tabs from the 7-char owner to col 32).
    ldns_pkt_ptr q = make_query("a.test", LDNS_RR_TYPE_A, true);
    ASSERT_NE(nullptr, q.get());
    DisplayFlags df;
    df.cmd = false;
    df.comments = false;
    df.question = true;
    df.answer = false;
    df.authority = false;
    df.additional = false;
    df.stats = false;
    std::string out = format_packet_dig(q.get(), df, false, Millis{0}, "");
    EXPECT_EQ(";a.test.\t\t\t\tIN\tA\n", out);
}

// --- bug #4: no blank line after OPT (OPT runs straight into QUESTION) ------

TEST(FormatPacketDig, OptRunsIntoQuestionWithoutBlank) {
    ldns_pkt_ptr q = make_test_query();
    CliOptions opts;
    opts.dnssec = true;
    opts.cookie = false; // isolate the OPT->QUESTION spacing (no COOKIE line)
    apply_dns_flags(q.get(), opts);
    std::string out = format_packet_dig(q.get(), {}, false, Millis{0}, "");
    EXPECT_TRUE(contains(out, "; EDNS: version: 0, flags: do; udp: 4096\n;; QUESTION SECTION:"));
    EXPECT_FALSE(contains(out, "udp: 4096\n\n;; QUESTION"));
}

// --- EDNS option decoding in the OPT PSEUDOSECTION -------------------------

TEST(FormatPacketDig, SubnetOptionDecoded) {
    // A query carrying +subnet renders `; CLIENT-SUBNET:` not the raw hex dump.
    ldns_pkt_ptr q = make_test_query();
    CliOptions opts;
    opts.subnet = {.enabled = true, .addr = "1.2.3.4", .src_prefix = 24};
    apply_dns_flags(q.get(), opts);
    std::string out = format_packet_dig(q.get(), {}, false, Millis{0}, "");
    EXPECT_TRUE(contains(out, "; CLIENT-SUBNET: 1.2.3.0/24/0"));
    EXPECT_FALSE(contains(out, "; DATA:"));
}

TEST(FormatPacketDig, EdeOptionDecoded) {
    ldns_pkt_ptr q = make_test_query();
    // TLV: option-code 15 (0x000F), len 2, data = info-code 20 (0x0014).
    Bytes ede{0x00, 0x0F, 0x00, 0x02, 0x00, 0x14};
    attach_edns(q.get(), 4096, ede);
    std::string out = format_packet_dig(q.get(), {}, false, Millis{0}, "");
    EXPECT_TRUE(contains(out, "; EDE: 20 (Not Authoritative)"));
}

// --- +header-only ----------------------------------------------------------

TEST(ApplyDnsFlags, HeaderOnlyStripsQuestionSection) {
    // `+header-only` mirrors `dig +header-only`: it sends a spec-compliant
    // header-only query (QDCOUNT=0, no question records). The question RR
    // added by make_query is removed here by apply_dns_flags.
    ldns_pkt_ptr q = make_test_query();
    ASSERT_NE(nullptr, q.get());
    ASSERT_EQ(1u, ldns_pkt_qdcount(q.get())); // question present before
    CliOptions opts;
    opts.header_only = true;
    opts.cookie = false;
    apply_dns_flags(q.get(), opts);
    EXPECT_EQ(0u, ldns_pkt_qdcount(q.get()));
    const ldns_rr_list *question = ldns_pkt_question(q.get());
    ASSERT_NE(nullptr, question);
    EXPECT_EQ(0u, ldns_rr_list_rr_count(question));
}

TEST(FormatPacketDig, HeaderOnlyShowsHeaderAndOptNotQuestion) {
    // The +header-only DISPLAY follows the normal display flags: the header
    // block and OPT PSEUDOSECTION are shown, empty sections are naturally
    // suppressed (no RRs), and stats are printed. This mirrors `dig
    // +header-only +qr`, which prints header + OPT + QUERY SIZE (not an early
    // return that hides everything after the header).
    ldns_pkt_ptr q = make_test_query();
    CliOptions opts;
    opts.dnssec = true;
    opts.header_only = true;
    opts.cookie = false;
    apply_dns_flags(q.get(), opts);
    EXPECT_EQ(0u, ldns_pkt_qdcount(q.get()));
    std::string out = format_packet_dig(q.get(), opts.display, false, Millis{42}, "1.1.1.1");
    EXPECT_TRUE(contains(out, "HEADER"));
    EXPECT_TRUE(contains(out, "QUERY: 0"));
    EXPECT_TRUE(contains(out, "OPT PSEUDOSECTION"));
    // Empty QUESTION SECTION has no RRs → section header suppressed by
    // print_section (mirrors dig suppressing empty sections entirely).
    EXPECT_FALSE(contains(out, "QUESTION SECTION"));
    // Stats are shown (not suppressed by +header-only).
    EXPECT_TRUE(contains(out, "Query time"));
    EXPECT_TRUE(contains(out, "MSG SIZE"));
}

// --- +onesoa ----------------------------------------------------------------

TEST(FormatPacketDig, OneSoaPrintsOnlyFirst) {
    // SOA rdata = mname rname serial refresh retry expire minimum (5 numbers).
    ldns_pkt_ptr pkt = make_answer_pkt({
            "example.com. 300 IN SOA ns1.example.com. hostmaster.example.com. 1 7200 3600 604800 86400",
            "example.com. 300 IN SOA ns2.example.com. hostmaster.example.com. 2 7200 3600 604800 86400",
    });
    DisplayFlags df;
    df.cmd = false;
    df.comments = false;
    df.question = false;
    df.answer = true;
    df.authority = false;
    df.additional = false;
    df.stats = false;
    df.one_soa = true;
    std::string out = format_packet_dig(pkt.get(), df, false, Millis{0}, "");
    EXPECT_EQ(1u, count_of(out, "\tSOA\t"));
    // Without +onesoa both SOAs are printed.
    df.one_soa = false;
    out = format_packet_dig(pkt.get(), df, false, Millis{0}, "");
    EXPECT_EQ(2u, count_of(out, "\tSOA\t"));
}

// --- +multiline -------------------------------------------------------------

TEST(FormatPacketDig, MultilineShortRecordByteExact) {
    // `dig +multiline` renders an A record as `owner<pad to col 24>300 IN A rdata`
    // (space-separated, two tabs for the 12-char owner). Verified against dig 9.20.
    ldns_pkt_ptr pkt = make_answer_pkt({"example.com. 300 IN A 1.2.3.4"});
    DisplayFlags df;
    df.cmd = false;
    df.comments = false;
    df.question = false;
    df.answer = true;
    df.authority = false;
    df.additional = false;
    df.stats = false;
    df.multiline = true;
    std::string out = format_packet_dig(pkt.get(), df, false, Millis{0}, "");
    EXPECT_EQ("example.com.\t\t300 IN A 1.2.3.4\n", out);
}

TEST(FormatPacketDig, MultilineTxtNeverWraps) {
    // `dig +multiline` does NOT wrap TXT records in `(` `)` — verified against
    // dig 9.20: a single 200-char TXT string or a 4-string TXT record both
    // stay on one line under +multiline. Only SOA / base64-or-hex-bearing
    // types (DS / KEY / RRSIG / SSHFP) get the `( ... )` wrapping treatment
    // in dig's per-type formatters. Previously adyg applied a generic
    // width-based parenthesization to every long RR type, which wrapped TXT
    // (incorrect) — verified dig never does. Two over-long TXT strings that
    // *would* have triggered the old wrapping now produce a single line.
    std::string a(56, 'a');
    std::string b(56, 'b');
    ldns_pkt_ptr pkt = make_answer_pkt({fmt::format("example.com. 300 IN TXT \"{}\" \"{}\"", a, b)});
    DisplayFlags df;
    df.cmd = false;
    df.comments = false;
    df.question = false;
    df.answer = true;
    df.authority = false;
    df.additional = false;
    df.stats = false;
    df.multiline = true;
    std::string out = format_packet_dig(pkt.get(), df, false, Millis{0}, "");
    EXPECT_FALSE(contains(out, " (\n"));
    EXPECT_FALSE(contains(out, std::string(4, '\t')));
    // The TXT string appears as one line, ending with `\n` (no `)`).
    EXPECT_TRUE(out.ends_with("\"" + b + "\"\n"));
}

// --- discrepancy #3: DS / CDS digest is uppercase hex (mirrors `dig`) -------

TEST(FormatPacketDig, DsDigestUppercased) {
    // dig's DS per-type formatter emits the digest (the trailing hex RDATA
    // field) in UPPERCASE; ldns's ldns_rdf2str renders hex as lowercase by
    // default. Verified against `dig example.com DS`:
    //   dig:  8ACBB0CD28F41250A80A491389424D341522D946B0DA0C0291F2D3D771D7805A
    //   adyg: 8acbb0cd28f41250a80a491389424d341522d946b0da0c0291f2d3d771d7805a
    // ldns's presentation parser lowercases the digest on input normalization
    // (the input case is irrelevant to ldns's storage), so the test works
    // regardless of the input case of the RR string.
    ldns_pkt_ptr pkt = make_answer_pkt({
            "com. 34518 IN DS 19718 13 2 8acbb0cd28f41250a80a491389424d341522d946b0da0c0291f2d3d771d7805a",
    });
    DisplayFlags df;
    df.cmd = false;
    df.comments = false;
    df.question = false;
    df.answer = true;
    df.authority = false;
    df.additional = false;
    df.stats = false;
    std::string out = format_packet_dig(pkt.get(), df, false, Millis{0}, "");
    // The leading three fields (key tag, algorithm, digest type) are decimal
    // integers, so case does not apply — verify they appear unchanged.
    EXPECT_TRUE(contains(out, "19718 13 2 "));
    // The trailing digest field is uppercased (the leading hex nibble `8A`,
    // the trailing `805A`, and at least one lowercase-to-uppercase mapping
    // mid-digest). The whole digest fragment appears as uppercase hex.
    EXPECT_TRUE(contains(out, "8ACBB0CD28F41250A80A491389424D341522D946B0DA0C0291F2D3D771D7805A"));
    // ... and the lowercase form must NOT appear (regression guard).
    EXPECT_FALSE(contains(out, "8acbb0cd"));
}

TEST(FormatPacketDig, CdsDigestUppercased) {
    // CDS (RFC 8078) shares DS's presentation format, so its digest is also
    // uppercased by dig's per-type formatter.
    ldns_pkt_ptr pkt = make_answer_pkt({
            "com. 300 IN CDS 19718 13 2 deadbeefcafe1234",
    });
    DisplayFlags df;
    df.cmd = false;
    df.comments = false;
    df.question = false;
    df.answer = true;
    df.authority = false;
    df.additional = false;
    df.stats = false;
    std::string out = format_packet_dig(pkt.get(), df, false, Millis{0}, "");
    EXPECT_TRUE(contains(out, "19718 13 2 DEADBEEFCAFE1234"));
    EXPECT_FALSE(contains(out, "deadbeef"));
}

// --- bug #4: SOA +multiline (per-field `; serial` / `; refresh (15 minutes)`) -

TEST(FormatPacketDig, MultilineSoaDefaultByteExact) {
    // dig 9.20 +multiline SOA output is byte-exact:
    //   owner<pad to col 24, 2 tabs for the 9-char "soa.test.">300 IN SOA ns1.test. admin.test. (\n
    //   <4 tabs>948229642  ; serial\n
    //   <4 tabs>900        ; refresh (15 minutes)\n
    //   <4 tabs>900        ; retry (15 minutes)\n
    //   <4 tabs>1800       ; expire (30 minutes)\n
    //   <4 tabs>60         ; minimum (1 minute)\n
    //   <4 tabs>)\n
    // The numeric value is `%-10lu` (10-col left-justified) followed by `; `.
    // refresh/retry/expire/minimum carry `; <name> (verbose-ttl)`; serial is
    // `; serial` (no time annotation). Verified against `dig +multiline`.
    ldns_pkt_ptr pkt = make_answer_pkt({
            "soa.test. 300 IN SOA ns1.test. admin.test. 948229642 900 900 1800 60",
    });
    DisplayFlags df;
    df.cmd = false;
    df.comments = false;
    df.question = false;
    df.answer = true;
    df.authority = false;
    df.additional = false;
    df.stats = false;
    df.multiline = true;
    std::string out = format_packet_dig(pkt.get(), df, false, Millis{0}, "");
    std::string expected = "soa.test.\t\t300 IN SOA ns1.test. admin.test. (\n"
                           "\t\t\t\t948229642  ; serial\n"
                           "\t\t\t\t900        ; refresh (15 minutes)\n"
                           "\t\t\t\t900        ; retry (15 minutes)\n"
                           "\t\t\t\t1800       ; expire (30 minutes)\n"
                           "\t\t\t\t60         ; minimum (1 minute)\n"
                           "\t\t\t\t)\n";
    EXPECT_EQ(expected, out);
}

TEST(FormatPacketDig, MultilineSoaNottlidPreservesIndentation) {
    // dig verified: `dig +multiline +nottlid` SOA layout is
    //   owner<pad>IN SOA\tns1.test. admin.test. (\n  ...
    // the type-to-RDATA separator is a TAB when the TTL column is absent (per
    // BIND's column-style (24, 24, 24, 32) under +nottlid +multiline).
    ldns_pkt_ptr pkt = make_answer_pkt({
            "soa.test. 300 IN SOA ns1.test. admin.test. 948229642 900 900 1800 60",
    });
    DisplayFlags df;
    df.cmd = false;
    df.comments = false;
    df.question = false;
    df.answer = true;
    df.authority = false;
    df.additional = false;
    df.stats = false;
    df.multiline = true;
    df.ttlid = false;
    std::string out = format_packet_dig(pkt.get(), df, false, Millis{0}, "");
    std::string expected = "soa.test.\t\tIN SOA\tns1.test. admin.test. (\n"
                           "\t\t\t\t948229642  ; serial\n"
                           "\t\t\t\t900        ; refresh (15 minutes)\n"
                           "\t\t\t\t900        ; retry (15 minutes)\n"
                           "\t\t\t\t1800       ; expire (30 minutes)\n"
                           "\t\t\t\t60         ; minimum (1 minute)\n"
                           "\t\t\t\t)\n";
    EXPECT_EQ(expected, out);
}

TEST(FormatPacketDig, MultilineSoaSerialPaddedToTenColumns) {
    // The `%-10lu` padding lines up the `;` across fields even when the
    // serial is wider/narrower than the others. A 10-digit serial sits
    // exactly at the column boundary, so only ONE space appears before the
    // `;`. Verified against `dig 9.20 +multiline` for example.com's SOA
    // (`2409709709 ; serial` — no extra padding).
    ldns_pkt_ptr pkt = make_answer_pkt({
            "example.com. 1800 IN SOA elliott.ns.cloudflare.com. dns.cloudflare.com. 2409709709 10000 2400 604800 1800",
    });
    DisplayFlags df;
    df.cmd = false;
    df.comments = false;
    df.question = false;
    df.answer = true;
    df.authority = false;
    df.additional = false;
    df.stats = false;
    df.multiline = true;
    std::string out = format_packet_dig(pkt.get(), df, false, Millis{0}, "");
    // The 10-digit serial must always sit exactly at the column boundary,
    // giving exactly ONE space before `; serial` (mirrors dig).
    EXPECT_TRUE(contains(out, "\t\t\t\t2409709709 ; serial\n"));
    EXPECT_TRUE(contains(out, "\t\t\t\t10000      ; refresh (2 hours 46 minutes 40 seconds)\n"));
    EXPECT_TRUE(contains(out, "\t\t\t\t2400       ; retry (40 minutes)\n"));
    EXPECT_TRUE(contains(out, "\t\t\t\t604800     ; expire (1 week)\n"));
    EXPECT_TRUE(contains(out, "\t\t\t\t1800       ; minimum (30 minutes)\n"));
    EXPECT_TRUE(contains(out, "\t\t\t\t)\n"));
}

TEST(FormatPacketDig, MultilineSoaTruncatedDoesNotCrash) {
    // A SOA whose RDATA is truncated on a field boundary (here: mname +
    // rname + serial only; refresh/retry/expire/minimum missing) is accepted
    // by ldns's wire parser — it parses as many fields as fit, so this RR has
    // rd_count == 3. ldns_rr_rdf() then returns NULL for indices >= 3, and
    // ldns_rdf2native_int32(NULL) is NOT null-safe (ldns_rdf_size asserts and,
    // with asserts compiled out in release, dereferences NULL). The +multiline
    // SOA path must therefore stop at the first missing numeric field rather
    // than blindly indexing all five. Presentation parsing rejects short SOAs,
    // so the truncated RR is built field-by-field (mirrors production
    // `create_soa` in upstream_system.cpp, but with 4 RDATA fields omitted).
    ldns_pkt_ptr pkt{ldns_pkt_new()};
    ldns_rr *rr = ldns_rr_new();
    ASSERT_NE(nullptr, rr);
    ldns_rr_set_type(rr, LDNS_RR_TYPE_SOA);
    ldns_rr_set_class(rr, LDNS_RR_CLASS_IN);
    ldns_rr_set_ttl(rr, 300);
    ldns_rr_set_owner(rr, ldns_dname_new_frm_str("soa.test."));
    // Only mname / rname / serial are pushed; refresh / retry / expire /
    // minimum are intentionally omitted so rd_count == 3 (a genuinely
    // truncated SOA, as the wire parser would produce for short RDATA).
    ldns_rr_push_rdf(rr, ldns_dname_new_frm_str("ns1.test."));
    ldns_rr_push_rdf(rr, ldns_dname_new_frm_str("admin.test."));
    ldns_rr_push_rdf(rr, ldns_native2rdf_int32(LDNS_RDF_TYPE_INT32, 948229642));
    ldns_pkt_push_rr(pkt.get(), LDNS_SECTION_ANSWER, rr); // takes ownership of rr
    ASSERT_EQ(3u, ldns_rr_rd_count(rr));

    DisplayFlags df;
    df.cmd = false;
    df.comments = false;
    df.question = false;
    df.answer = true;
    df.authority = false;
    df.additional = false;
    df.stats = false;
    df.multiline = true;
    std::string out = format_packet_dig(pkt.get(), df, false, Millis{0}, "");

    // The serial (present in RDATA) is rendered and the per-field block is
    // closed with `)`; the four missing numeric fields are NOT fabricated.
    // (Reaching these assertions at all confirms the NULL deref did not occur.)
    EXPECT_TRUE(contains(out, "soa.test.\t\t300 IN SOA ns1.test. admin.test. (\n"));
    EXPECT_TRUE(contains(out, "\t\t\t\t948229642  ; serial\n"));
    EXPECT_TRUE(contains(out, "\t\t\t\t)\n"));
    EXPECT_FALSE(contains(out, "; refresh"));
    EXPECT_FALSE(contains(out, "; retry"));
    EXPECT_FALSE(contains(out, "; expire"));
    EXPECT_FALSE(contains(out, "; minimum"));
}

// --- bug #9: +qr query-echo uses `QUERY SIZE:` (not `MSG SIZE  sent:`) -------

TEST(FormatPacketDig, QueryEchoUsesQuerySizeLabel) {
    // dig 9.20 verified: the +qr query-echo stats line is `;; QUERY SIZE: N`,
    // not `;; MSG SIZE  sent: N` (the response uses `;; MSG SIZE  rcvd: N`).
    // The `MSG SIZE  rcvd:` form still applies to the response (the double
    // space in `MSG SIZE` aligns its colon with `QUERY SIZE:`'s).
    ldns_pkt_ptr q = make_test_query();
    std::string query_out = format_packet_dig(q.get(), {}, true, Millis{0}, "");
    EXPECT_TRUE(contains(query_out, ";; QUERY SIZE:"));
    EXPECT_FALSE(contains(query_out, "MSG SIZE"));
    EXPECT_FALSE(contains(query_out, "sent:"));
    std::string response_out = format_packet_dig(q.get(), {}, false, Millis{0}, "");
    EXPECT_TRUE(contains(response_out, ";; MSG SIZE  rcvd:"));
    EXPECT_FALSE(contains(response_out, "QUERY SIZE"));
}

// --- discrepancy #7: +qr query echo's stats block is separated from the
// response by a blank line (mirrors `dig +qr +noall +stats`) ----------------

TEST(FormatPacketDig, QueryEchoStatsTrailingBlankLine) {
    // dig's `+qr` output puts a blank line between the query echo's stats
    // block (`;; QUERY SIZE: N`) and the response's stats block (`;; Query
    // time:` / `;; SERVER:` / ...). Verified against `dig +qr +noall +stats`:
    // the query echo ends with `;; QUERY SIZE: N\n` followed by a blank line,
    // so the response's `;; Query time:` is separated by exactly one empty
    // line. Previously adyg omitted this blank line, yielding consecutive
    // `QUERY SIZE:` / `Query time:` lines with no separator.
    ldns_pkt_ptr q = make_test_query();
    // +qr +noall +stats: only the stats block is on; sections/comments off.
    DisplayFlags df;
    df.cmd = false;
    df.comments = false;
    df.question = false;
    df.answer = false;
    df.authority = false;
    df.additional = false;
    df.stats = true;
    std::string query_out = format_packet_dig(q.get(), df, true, Millis{0}, "");
    // The query echo ends with `;; QUERY SIZE: N\n` + the separator blank line
    // (`\n`), giving a trailing `\n\n`.
    EXPECT_TRUE(contains(query_out, ";; QUERY SIZE:"));
    EXPECT_TRUE(query_out.ends_with(";; QUERY SIZE: 29\n\n"));
    // The response path (is_query=false) is unaffected — no extra blank line.
    std::string response_out = format_packet_dig(q.get(), df, false, Millis{0}, "");
    EXPECT_FALSE(response_out.ends_with("\n\n"));
}

// --- format_trace_received_line -------------------------------------------
//
// Mirrors dig's `;; Received N bytes from IP#53(NAME) in Y ms`. The NAME in
// parens repeats the IP when no hostname is known (mirroring dig when the
// peer has no resolvable reverse-DNS name).

TEST(FormatTraceReceivedLine, WithServerName) {
    std::string line = format_trace_received_line(Millis{42}, 239, "198.41.0.4", "a.root-servers.net");
    EXPECT_EQ(line, ";; Received 239 bytes from 198.41.0.4#53(a.root-servers.net) in 42 ms\n");
}

TEST(FormatTraceReceivedLine, EmptyNameRepeatsIp) {
    std::string line = format_trace_received_line(Millis{5}, 72, "1.1.1.1", "");
    EXPECT_EQ(line, ";; Received 72 bytes from 1.1.1.1#53(1.1.1.1) in 5 ms\n");
}

TEST(FormatTraceReceivedLine, NonZeroTimePrintedAsCount) {
    std::string line = format_trace_received_line(Millis{1000}, 1, "1.2.3.4", "ns.example.");
    EXPECT_TRUE(contains(line, "in 1000 ms"));
}

// --- format_trace_packet_dig (per-hop trace output) ----------------------
//
// dig's default `+trace` output is: per-hop RRs (no section headers, no
// QUESTION, no stats block) followed by the `Received ... bytes from ...`
// footer. With `+stats` the footer is replaced by the standard
// `Query time / SERVER (as IP#53(name) (proto)) / MSG SIZE` block, where `proto`
// reflects the `tcp` argument (UDP by default; TCP under `+tcp`).

TEST(FormatTracePacketDig, DefaultEmitsReceivedFooter) {
    // Mirror the trace-default display state (+trace clears comments,
    // question, stats in parse_args): use apply_trace_display_defaults so the
    // test and the parse_args-driven main() see the same flags.
    ldns_pkt_ptr q = make_test_query();
    DisplayFlags df;
    apply_trace_display_defaults(df);
    std::string out = format_trace_packet_dig(q.get(), df, Millis{42}, "198.41.0.4", "a.root-servers.net");
    // Trace default body: no comments, no question, no stats — RRs only.
    EXPECT_FALSE(contains(out, "Got answer:"));
    EXPECT_FALSE(contains(out, "HEADER"));
    EXPECT_FALSE(contains(out, "QUESTION SECTION:"));
    EXPECT_FALSE(contains(out, "ANSWER SECTION:"));
    EXPECT_FALSE(contains(out, "Query time:"));
    EXPECT_FALSE(contains(out, "SERVER:"));
    EXPECT_FALSE(contains(out, "MSG SIZE"));
    // ... and the trace-specific Received footer using the dig IP#53(name) form.
    EXPECT_TRUE(contains(out, "Received "));
    EXPECT_TRUE(contains(out, "bytes from 198.41.0.4#53(a.root-servers.net) in 42 ms"));
    // Trailing blank line separates this hop from the next.
    EXPECT_TRUE(out.ends_with("\n\n"));
}

TEST(FormatTracePacketDig, EmptyNameFallsBackToIpInFooter) {
    ldns_pkt_ptr q = make_test_query();
    DisplayFlags df;
    apply_trace_display_defaults(df);
    std::string out = format_trace_packet_dig(q.get(), df, Millis{1}, "1.1.1.1", "");
    EXPECT_TRUE(contains(out, "1.1.1.1#53(1.1.1.1)"));
}

TEST(FormatTracePacketDig, StatsEnabledEmitsStandardFooter) {
    // When +stats / +all re-enables the stats block (overriding the trace
    // default), the trace footer is replaced by the standard stats trailer
    // using the dig server formatting (IP#53(name) (UDP)) rather than the
    // bare `opts.server`.
    ldns_pkt_ptr q = make_test_query();
    DisplayFlags df;
    apply_trace_display_defaults(df);
    df.stats = true; // mirror `+trace +stats` / `+trace +all`
    std::string out = format_trace_packet_dig(q.get(), df, Millis{87}, "192.5.5.241", "f.root-servers.net");
    EXPECT_FALSE(contains(out, "Received")); // No Received footer with +stats.
    EXPECT_TRUE(contains(out, ";; Query time: 87 msec"));
    EXPECT_TRUE(contains(out, ";; SERVER: 192.5.5.241#53(f.root-servers.net) (UDP)"));
    EXPECT_TRUE(contains(out, ";; MSG SIZE  rcvd:"));
    EXPECT_TRUE(out.ends_with("\n\n"));
}

TEST(FormatTracePacketDig, StatsFooterTcpRendersTcpTransport) {
    // Regression: `+trace +tcp +stats` rewrites every hop to `tcp://` in
    // run_trace (opts.force_tcp), so the stats footer's `;; SERVER:` line must
    // render `(TCP)` — not the hardcoded `(UDP)` — for those hops. Mirrors the
    // scheme-driven transport in format_dig_server.
    ldns_pkt_ptr q = make_test_query();
    DisplayFlags df;
    apply_trace_display_defaults(df);
    df.stats = true; // mirror `+trace +tcp +stats`
    std::string out = format_trace_packet_dig(q.get(), df, Millis{12}, "198.41.0.4", "a.root-servers.net", true);
    EXPECT_FALSE(contains(out, "(UDP)"));
    EXPECT_TRUE(contains(out, ";; SERVER: 198.41.0.4#53(a.root-servers.net) (TCP)"));
    EXPECT_TRUE(contains(out, ";; Query time: 12 msec"));
    EXPECT_TRUE(contains(out, ";; MSG SIZE  rcvd:"));
    EXPECT_TRUE(out.ends_with("\n\n"));
}

TEST(FormatTracePacketDig, StatsFooterTcpFalseRendersUdpTransport) {
    // The default `tcp=false` (the trace default) renders `(UDP)` in the stats
    // footer even when an empty name falls back to the IP, so the transport is
    // driven by the `tcp` argument rather than assumed.
    ldns_pkt_ptr q = make_test_query();
    DisplayFlags df;
    apply_trace_display_defaults(df);
    df.stats = true;
    std::string out = format_trace_packet_dig(q.get(), df, Millis{3}, "1.1.1.1", "");
    EXPECT_FALSE(contains(out, "(TCP)"));
    EXPECT_TRUE(contains(out, ";; SERVER: 1.1.1.1#53(1.1.1.1) (UDP)"));
}

TEST(FormatTracePacketDig, CommentsEnabledShowsSectionHeaders) {
    // `+trace +comments` re-enables only the comments toggle; the trace-default
    // toggles for `question` and `stats` are still off, so the body shows the
    // `Got answer:` header (and any populated section header) above the
    // per-hop RRs but no QUESTION section / no stats trailer. Mirrors
    // `dig +trace +comments`.
    ldns_pkt_ptr q = make_test_query();
    DisplayFlags df;
    apply_trace_display_defaults(df);
    df.comments = true;
    std::string out = format_trace_packet_dig(q.get(), df, Millis{1}, "1.1.1.1", "");
    // comments re-enabled: header (over the is_query=false body) appears.
    EXPECT_TRUE(contains(out, "Got answer:"));
    EXPECT_TRUE(contains(out, "HEADER"));
    // question still off (trace default), so the QUESTION section is gone.
    EXPECT_FALSE(contains(out, "QUESTION SECTION:"));
    // stats is still off (trace default), so the Received footer is emitted
    // and the standard Query time / SERVER block is not.
    EXPECT_TRUE(contains(out, "Received "));
    EXPECT_FALSE(contains(out, "Query time:"));
}

// --- additional_glue (A preferred over AAAA; family tagging) ----------------
//
// +trace pairs NS target names with their ADDITIONAL-section glue. A later AAAA
// must not displace an earlier A for the same owner (so +trace doesn't prefer
// IPv6 when IPv4 glue is present and the chosen address is order-independent),
// and each entry must be tagged with its family so -4 can skip IPv6 glue.

TEST(AdditionalGlue, PrefersAOverAaaaRegardlessOfOrder) {
    const std::string owner = "ns1.example.net.";
    // Both orderings: the A record must win over the AAAA for the same owner.
    for (int order = 0; order < 2; ++order) {
        const char *a_rr = "ns1.example.net. 300 IN A 1.2.3.4";
        const char *aaaa_rr = "ns1.example.net. 300 IN AAAA 2001:db8::1";
        ldns_pkt_ptr pkt = make_glue_pkt({order == 0 ? a_rr : aaaa_rr, order == 0 ? aaaa_rr : a_rr});
        auto glue = additional_glue(pkt.get());
        ASSERT_EQ(1u, glue.size()) << "order=" << order;
        auto it = glue.find(owner);
        ASSERT_NE(it, glue.end()) << "order=" << order;
        EXPECT_EQ("1.2.3.4", it->second.address) << "order=" << order;
        EXPECT_FALSE(it->second.ipv6) << "order=" << order;
    }
}

TEST(AdditionalGlue, KeepsARecord) {
    ldns_pkt_ptr pkt = make_glue_pkt({"ns3.example.net. 300 IN A 9.9.9.9"});
    auto glue = additional_glue(pkt.get());
    ASSERT_EQ(1u, glue.size());
    auto it = glue.find("ns3.example.net.");
    ASSERT_NE(it, glue.end());
    EXPECT_EQ("9.9.9.9", it->second.address);
    EXPECT_FALSE(it->second.ipv6);
}

TEST(AdditionalGlue, KeepsAaaaWhenNoA) {
    // No A for this owner, so the AAAA is kept (and tagged IPv6).
    ldns_pkt_ptr pkt = make_glue_pkt({"ns2.example.net. 300 IN AAAA 2001:db8::1"});
    auto glue = additional_glue(pkt.get());
    ASSERT_EQ(1u, glue.size());
    auto it = glue.find("ns2.example.net.");
    ASSERT_NE(it, glue.end());
    EXPECT_EQ(render_ip(LDNS_RDF_TYPE_AAAA, "2001:db8::1"), it->second.address);
    EXPECT_TRUE(it->second.ipv6);
}

TEST(AdditionalGlue, IgnoresNonGlueAndKeepsMultipleOwners) {
    // Only A/AAAA glue is extracted; NS/TXT (and any other) ADDITIONAL RRs are
    // ignored. Multiple owners each get their own entry.
    ldns_pkt_ptr pkt = make_glue_pkt({
            "ns1.example.net. 300 IN A 1.1.1.1",
            "ns2.example.net. 300 IN AAAA 2001:db8::2",
            "example.net. 300 IN NS ns1.example.net.", // NS in ADDITIONAL: ignored
            "example.net. 300 IN TXT \"not-glue\"",    // TXT: ignored
    });
    auto glue = additional_glue(pkt.get());
    EXPECT_EQ(2u, glue.size());
    EXPECT_EQ("1.1.1.1", glue["ns1.example.net."].address);
    EXPECT_FALSE(glue["ns1.example.net."].ipv6);
    EXPECT_TRUE(glue["ns2.example.net."].ipv6);
}

TEST(AdditionalGlue, NullAndEmptyPackets) {
    EXPECT_TRUE(additional_glue(nullptr).empty());
    ldns_pkt_ptr empty{ldns_pkt_new()};
    ASSERT_NE(nullptr, empty.get());
    EXPECT_TRUE(additional_glue(empty.get()).empty());
}

// --- glue_address_usable (-4 suppresses IPv6 glue) -------------------------

TEST(GlueAddressUsable, Ipv4AlwaysUsable) {
    GlueAddress a{.address = "1.2.3.4", .ipv6 = false};
    EXPECT_TRUE(glue_address_usable(a, false));
    EXPECT_TRUE(glue_address_usable(a, true)); // -4 does not suppress IPv4
}

TEST(GlueAddressUsable, Ipv6SuppressedUnderIpv4Only) {
    GlueAddress aaaa{.address = "2001:db8::1", .ipv6 = true};
    EXPECT_TRUE(glue_address_usable(aaaa, false)); // no -4: IPv6 is fine
    EXPECT_FALSE(glue_address_usable(aaaa, true)); // -4: IPv6 suppressed
}

// --- SERVER formatting (format_dig_server) ---------------------------------

TEST(FormatDigServer, PlainIpUdp) {
    EXPECT_EQ("1.1.1.1#53(1.1.1.1) (UDP)", format_dig_server("1.1.1.1", std::nullopt, false));
}

TEST(FormatDigServer, PlainIpTcp) {
    EXPECT_EQ("1.1.1.1#53(1.1.1.1) (TCP)", format_dig_server("1.1.1.1", std::nullopt, true));
}

TEST(FormatDigServer, PortOverrideFromDashP) {
    EXPECT_EQ("1.1.1.1#5353(1.1.1.1) (UDP)", format_dig_server("1.1.1.1", 5353, false));
}

TEST(FormatDigServer, ExplicitPortInServer) {
    EXPECT_EQ("1.1.1.1#53(1.1.1.1) (UDP)", format_dig_server("1.1.1.1:53", std::nullopt, false));
    EXPECT_EQ("1.1.1.1#5353(1.1.1.1) (UDP)", format_dig_server("1.1.1.1:53", 5353, false));
}

TEST(FormatDigServer, BracketedIpv6WithPort) {
    // Regression: `[::1]:53` has 2+ colons, so the single-colon path did not
    // split the explicit port — the SERVER line showed the raw `[::1]:53` rather
    // than `::1#53(::1) (UDP)`. split_plain_host_port now handles the
    // `[v6]:port` form (extracting port 53, leaving `[::1]` as the host), and
    // format_dig_server strips the brackets for dig-compatible display (dig
    // renders `::1`, not `[::1]`). A `-p` override now also takes effect.
    EXPECT_EQ("::1#53(::1) (UDP)", format_dig_server("[::1]:53", std::nullopt, false));
    EXPECT_EQ("::1#5353(::1) (UDP)", format_dig_server("[::1]:53", 5353, false));
    EXPECT_EQ("::1#53(::1) (UDP)", format_dig_server("[::1]", std::nullopt, false));
    EXPECT_EQ("::1#5353(::1) (UDP)", format_dig_server("[::1]", 5353, false));
    // Full IPv6 literal and TCP transport.
    EXPECT_EQ("2001:db8::1#53(2001:db8::1) (UDP)", format_dig_server("[2001:db8::1]", std::nullopt, false));
    EXPECT_EQ("::1#53(::1) (TCP)", format_dig_server("[::1]", std::nullopt, true));
}

TEST(FormatDigServer, HostnameWithoutDotExplicitPort) {
    // Regression: the old dot-guard skipped the port split for a dot-less host,
    // yielding `localhost:53#53(localhost:53) (UDP)`. The single-colon split now
    // extracts the port properly.
    EXPECT_EQ("localhost#53(localhost) (UDP)", format_dig_server("localhost:53", std::nullopt, false));
    EXPECT_EQ("localhost#5353(localhost) (UDP)", format_dig_server("localhost:53", 5353, false));
    EXPECT_EQ("localhost#5353(localhost) (UDP)", format_dig_server("localhost", 5353, false));
}

TEST(FormatDigServer, SchemedServerRaw) {
    EXPECT_EQ("tls://dns.adguard.com", format_dig_server("tls://dns.adguard.com", 5353, true));
    EXPECT_EQ("system://", format_dig_server("system://", std::nullopt, false));
}

TEST(FormatDigServer, PlainDnsSchemeStripped) {
    // Regression: apply_force_tcp rewrites `@1.1.1.1 +tcp` to `tcp://1.1.1.1`
    // *before* the SERVER line is formatted, so the scheme must be stripped
    // (rather than echoed raw) to produce dig's `IP#port(host) (TCP)` form. The
    // protocol is derived from the scheme, not the `tcp` parameter.
    EXPECT_EQ("1.1.1.1#53(1.1.1.1) (TCP)", format_dig_server("tcp://1.1.1.1", std::nullopt, false));
    EXPECT_EQ("1.1.1.1#5353(1.1.1.1) (TCP)", format_dig_server("tcp://1.1.1.1:5353", std::nullopt, false));
    EXPECT_EQ("1.1.1.1#5353(1.1.1.1) (TCP)", format_dig_server("tcp://1.1.1.1", 5353, false));
    EXPECT_EQ("1.1.1.1#53(1.1.1.1) (UDP)", format_dig_server("udp://1.1.1.1", std::nullopt, true));
    EXPECT_EQ("1.1.1.1#53(1.1.1.1) (UDP)", format_dig_server("dns://1.1.1.1", std::nullopt, true));
    // The scheme match is case-insensitive (mirrors upstream scheme parsing).
    EXPECT_EQ("1.1.1.1#53(1.1.1.1) (TCP)", format_dig_server("TCP://1.1.1.1", std::nullopt, false));
}

TEST(FormatDigServer, BracketedIpv6AfterForceTcp) {
    // End-to-end: `@[::1]:53 -p 5353 +tcp` -> apply_port keeps the brackets
    // (`[::1]:5353`), apply_force_tcp prefixes `tcp://` (`tcp://[::1]:5353`),
    // and format_dig_server strips the scheme and the brackets for dig-style
    // `::1#5353(::1) (TCP)`. Without the bracket handling, the explicit port
    // could not be overridden and the SERVER line would show `[::1]:53`.
    EXPECT_EQ("::1#5353(::1) (TCP)", format_dig_server("tcp://[::1]:5353", std::nullopt, false));
    EXPECT_EQ("::1#53(::1) (TCP)", format_dig_server("tcp://[::1]", std::nullopt, false));
}

TEST(FormatDigServer, EmptyReturnsEmpty) {
    EXPECT_TRUE(format_dig_server("", std::nullopt, false).empty());
}

// --- WHEN formatting (format_dig_when) -------------------------------------

TEST(FormatDigWhen, ZeroOmitted) {
    EXPECT_TRUE(format_dig_when(0).empty());
}

TEST(FormatDigWhen, NonzeroHasTime) {
    std::string s = format_dig_when(std::time(nullptr));
    ASSERT_FALSE(s.empty());
    EXPECT_NE(std::string::npos, s.find(':')); // HH:MM:SS
}

TEST(FormatDigWhen, SingleDigitDaySpacePadded) {
    // dig space-pads a single-digit day (` 5`) rather than strftime's zero pad
    // (`05`). The day insertion is now locale-independent (no longer assumes
    // `%a`/`%b` are exactly 3 chars). 2026-01-05 12:00:00 local.
    std::tm tm{};
    tm.tm_year = 2026 - 1900;
    tm.tm_mon = 0; // January
    tm.tm_mday = 5;
    tm.tm_hour = 12;
    tm.tm_min = 0;
    tm.tm_sec = 0;
    tm.tm_isdst = -1;
    std::time_t t = std::mktime(&tm);
    ASSERT_FALSE(t == static_cast<std::time_t>(-1));
    std::string s = format_dig_when(t);
    ASSERT_FALSE(s.empty());
    EXPECT_EQ(std::string::npos, s.find("05")); // not zero-padded
    EXPECT_NE(std::string::npos, s.find(" 5")); // space-padded day present
    EXPECT_NE(std::string::npos, s.find("12:00:00"));
}

TEST(FormatDigWhen, TwoDigitDayNotPadded) {
    // 2026-01-16 12:00:00 local — a two-digit day is emitted without a leading
    // space swap.
    std::tm tm{};
    tm.tm_year = 2026 - 1900;
    tm.tm_mon = 0;
    tm.tm_mday = 16;
    tm.tm_hour = 12;
    tm.tm_min = 0;
    tm.tm_sec = 0;
    tm.tm_isdst = -1;
    std::time_t t = std::mktime(&tm);
    ASSERT_FALSE(t == static_cast<std::time_t>(-1));
    std::string s = format_dig_when(t);
    ASSERT_FALSE(s.empty());
    EXPECT_NE(std::string::npos, s.find("16"));
    EXPECT_NE(std::string::npos, s.find("12:00:00"));
}

} // namespace ag::adyg::test
