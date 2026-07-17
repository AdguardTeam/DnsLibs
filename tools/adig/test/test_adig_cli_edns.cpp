// Unit tests for adig's pure CLI layer — EDNS/IP helpers.
//
// One of the split test translation units registered in
// tools/adig/CMakeLists.txt. It covers the functions implemented in
// adig_cli_edns.cpp: encode_ecs_option / encode_edns_option, the
// parse_ednsopt_code mnemonic table, decode_hex_string, make_reverse_name,
// parse_opcode_name, format_dns_ttl_units and format_edns_option_text.
// Parsing tests live in test_adig_cli.cpp and packet/format tests in
// test_adig_cli_packet.cpp. Shared helpers are in test_adig_cli_helpers.h.

#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "adig_cli.h"
#include "test_adig_cli_helpers.h"

namespace ag::adig::test {

// --- encode_ecs_option (RFC 7871, byte-exact) ----------------------------

TEST(EncodeEcsOption, Ipv4Prefix24) {
    // code=8, len=7, family=1, src=24(0x18), scope=0, addr=01 02 03
    EXPECT_EQ((Bytes{0x00, 0x08, 0x00, 0x07, 0x00, 0x01, 0x18, 0x00, 0x01, 0x02, 0x03}),
            encode_ecs_option("1.2.3.4", 24));
}

TEST(EncodeEcsOption, Ipv4Prefix8And16) {
    EXPECT_EQ((Bytes{0x00, 0x08, 0x00, 0x05, 0x00, 0x01, 0x08, 0x00, 0x01}), encode_ecs_option("1.2.3.4", 8));
    EXPECT_EQ((Bytes{0x00, 0x08, 0x00, 0x06, 0x00, 0x01, 0x10, 0x00, 0x01, 0x02}), encode_ecs_option("1.2.3.4", 16));
}

TEST(EncodeEcsOption, Ipv4Prefix17MasksTrailingBits) {
    // prefix=17 -> 3 bytes, last byte keeps only the top 1 bit; 0x03 & 0x80 = 0x00
    EXPECT_EQ((Bytes{0x00, 0x08, 0x00, 0x07, 0x00, 0x01, 0x11, 0x00, 0x01, 0x02, 0x00}),
            encode_ecs_option("1.2.3.4", 17));
}

TEST(EncodeEcsOption, Ipv4ZeroPrefixSentinel) {
    // 0.0.0.0/0 -> family 1, prefix 0, empty address
    EXPECT_EQ((Bytes{0x00, 0x08, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00}), encode_ecs_option("0.0.0.0", 0));
}

TEST(EncodeEcsOption, Ipv6Prefix64) {
    // 2001:db8::1 -> first 8 bytes = 20 01 0d b8 00 00 00 00; family=2, src=64(0x40)
    EXPECT_EQ((Bytes{0x00, 0x08, 0x00, 0x0C, 0x00, 0x02, 0x40, 0x00, 0x20, 0x01, 0x0D, 0xB8, 0x00, 0x00, 0x00, 0x00}),
            encode_ecs_option("2001:db8::1", 64));
}

TEST(EncodeEcsOption, Ipv6ZeroPrefixSentinel) {
    EXPECT_EQ((Bytes{0x00, 0x08, 0x00, 0x04, 0x00, 0x02, 0x00, 0x00}), encode_ecs_option("::", 0));
}

TEST(EncodeEcsOption, InvalidAddressOrPrefixReturnsEmpty) {
    EXPECT_TRUE(encode_ecs_option("example.com", 24).empty());
    EXPECT_TRUE(encode_ecs_option("999.1.1.1", 24).empty());
    EXPECT_TRUE(encode_ecs_option("1.2.3.4", 40).empty()); // prefix > 32
    EXPECT_TRUE(encode_ecs_option("::1", 200).empty());    // prefix > 128
}

// --- make_reverse_name ----------------------------------------------------

TEST(MakeReverseName, Ipv4) {
    EXPECT_EQ("4.3.2.1.in-addr.arpa.", make_reverse_name("1.2.3.4").value_or(""));
    EXPECT_EQ("8.8.8.8.in-addr.arpa.", make_reverse_name("8.8.8.8").value_or(""));
    // Full IPv4 with a trailing component.
    EXPECT_EQ("10.0.0.1.in-addr.arpa.", make_reverse_name("1.0.0.10").value_or(""));
}

TEST(MakeReverseName, Ipv6) {
    EXPECT_EQ("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.",
            make_reverse_name("::1").value_or(""));
    // 2001:db8::1 -> reversed nibbles end with 8.b.d.0.1.0.0.2.ip6.arpa.
    std::string v6 = make_reverse_name("2001:db8::1").value_or("");
    EXPECT_EQ(std::string::npos, v6.find_first_not_of("0123456789abcdef.ip6arpa."));
    EXPECT_TRUE(v6.ends_with("8.b.d.0.1.0.0.2.ip6.arpa."));
    EXPECT_TRUE(v6.starts_with("1.0."));
}

TEST(MakeReverseName, InvalidReturnsNullopt) {
    EXPECT_FALSE(make_reverse_name("").has_value());
    EXPECT_FALSE(make_reverse_name("example.com").has_value());
    EXPECT_FALSE(make_reverse_name("999.1.1.1").has_value());
    EXPECT_FALSE(make_reverse_name("1.2.3").has_value());
    EXPECT_FALSE(make_reverse_name("::g").has_value());
}

// --- encode_edns_option (generic TLV) --------------------------------------

TEST(EncodeEdnsOption, GenericTlv) {
    EXPECT_EQ((Bytes{0x00, 0x03, 0x00, 0x00}), encode_edns_option(0x03, nullptr, 0));
    std::vector<uint8_t> data{0xAA, 0xBB};
    EXPECT_EQ((Bytes{0x00, 0x0C, 0x00, 0x02, 0xAA, 0xBB}), encode_edns_option(0x0C, data.data(), data.size()));
    // Big option code (0x0102) encodes high byte first.
    EXPECT_EQ((Bytes{0x01, 0x02, 0x00, 0x00}), encode_edns_option(0x0102, nullptr, 0));
}

// --- +ednsopt=CODE resolution (parse_ednsopt_code) -------------------------
//
// `dig +ednsopt=CODE[:hexvalue]`: CODE is a case-insensitive mnemonic mapped
// to its RFC code (mirroring dig's `optnames` table) or a decimal number
// (0..65535).

TEST(ParseEdnsoptCode, MnemonicsResolve) {
    EXPECT_EQ(3u, parse_ednsopt_code("NSID").value_or(0));
    EXPECT_EQ(8u, parse_ednsopt_code("ECS").value_or(0));
    EXPECT_EQ(12u, parse_ednsopt_code("PADDING").value_or(0));
    EXPECT_EQ(12u, parse_ednsopt_code("PAD").value_or(0)); // shorthand
    EXPECT_EQ(10u, parse_ednsopt_code("COOKIE").value_or(0));
    EXPECT_EQ(15u, parse_ednsopt_code("EDE").value_or(0));
    EXPECT_EQ(11u, parse_ednsopt_code("KEEPALIVE").value_or(0));
    EXPECT_EQ(9u, parse_ednsopt_code("EXPIRE").value_or(0));
    EXPECT_EQ(13u, parse_ednsopt_code("CHAIN").value_or(0));
    EXPECT_EQ(14u, parse_ednsopt_code("KEY-TAG").value_or(0));
    EXPECT_EQ(18u, parse_ednsopt_code("REPORT-CHANNEL").value_or(0));
    EXPECT_EQ(18u, parse_ednsopt_code("RC").value_or(0)); // shorthand
    EXPECT_EQ(19u, parse_ednsopt_code("ZONEVERSION").value_or(0));
    EXPECT_EQ(26946u, parse_ednsopt_code("DEVICEID").value_or(0));
    EXPECT_EQ(2u, parse_ednsopt_code("UL").value_or(0));
    EXPECT_EQ(2u, parse_ednsopt_code("UPDATE-LEASE").value_or(0));
}

TEST(ParseEdnsoptCode, CaseInsensitive) {
    EXPECT_EQ(3u, parse_ednsopt_code("nsid").value_or(0));
    EXPECT_EQ(3u, parse_ednsopt_code("Nsid").value_or(0));
    EXPECT_EQ(3u, parse_ednsopt_code("nSiD").value_or(0));
    EXPECT_EQ(12u, parse_ednsopt_code("padding").value_or(0));
}

TEST(ParseEdnsoptCode, DecimalNumeric) {
    EXPECT_EQ(3u, parse_ednsopt_code("3").value_or(0));
    EXPECT_EQ(12u, parse_ednsopt_code("12").value_or(0));
    EXPECT_EQ(0u, parse_ednsopt_code("0").value_or(1));
    EXPECT_EQ(65535u, parse_ednsopt_code("65535").value_or(0));
    EXPECT_EQ(99u, parse_ednsopt_code("99").value_or(0)); // unassigned, still valid
    // DEVICEID (26946) fits in uint16_t, so the numeric form resolves too — it
    // is not mnemonic-only (documents the corrected comment).
    EXPECT_EQ(26946u, parse_ednsopt_code("26946").value_or(0));
}

TEST(ParseEdnsoptCode, InvalidRejected) {
    EXPECT_FALSE(parse_ednsopt_code("").has_value());
    EXPECT_FALSE(parse_ednsopt_code("NSIDX").has_value()); // unknown mnemonic
    EXPECT_FALSE(parse_ednsopt_code("BOGUS").has_value());
    EXPECT_FALSE(parse_ednsopt_code("65536").has_value()); // out of range
    EXPECT_FALSE(parse_ednsopt_code("-1").has_value());
    EXPECT_FALSE(parse_ednsopt_code("0x3").has_value()); // hex prefix not accepted (decimal only, like dig)
    EXPECT_FALSE(parse_ednsopt_code("3.5").has_value());
    EXPECT_FALSE(parse_ednsopt_code("1 2").has_value()); // whitespace is not a valid numeric code
}

// --- decode_hex_string (ISC isc_hex_decodestring mirror) -------------------

TEST(DecodeHexString, HexToBytes) {
    EXPECT_EQ((Bytes{0x41, 0x42}), decode_hex_string("4142").value_or(Bytes{}));
    EXPECT_EQ((Bytes{0xab, 0xcd}), decode_hex_string("abcd").value_or(Bytes{}));
    EXPECT_EQ((Bytes{0xab, 0xcd}), decode_hex_string("ABCD").value_or(Bytes{})); // upper case
    EXPECT_EQ((Bytes{0x01, 0x0a, 0xff}), decode_hex_string("010aff").value_or(Bytes{}));
    EXPECT_EQ(Bytes{}, decode_hex_string("").value_or(Bytes{'x'})); // empty = empty payload
}

TEST(DecodeHexString, WhitespaceIgnored) {
    // ASCII whitespace (space/tab/newline/CR) is skipped, mirroring ISC's decoder.
    EXPECT_EQ((Bytes{0x41, 0x42}), decode_hex_string("41 42").value_or(Bytes{}));
    EXPECT_EQ((Bytes{0x41, 0x42}), decode_hex_string("41\t42").value_or(Bytes{}));
    EXPECT_EQ((Bytes{0x41, 0x42}), decode_hex_string("\n41\r\n42\t").value_or(Bytes{}));
}

TEST(DecodeHexString, OddAndNonHexRejected) {
    EXPECT_FALSE(decode_hex_string("4").has_value());    // odd number of digits
    EXPECT_FALSE(decode_hex_string("414").has_value());  // odd after a complete pair
    EXPECT_FALSE(decode_hex_string("41 4").has_value()); // odd after stripping whitespace
    EXPECT_FALSE(decode_hex_string("4g").has_value());   // non-hex character
    EXPECT_FALSE(decode_hex_string("ZZ").has_value());
    EXPECT_FALSE(decode_hex_string("414g").has_value());
}

// --- format_dns_ttl_units (+ttlunits) --------------------------------------

TEST(FormatDnsTtlUnits, HumanReadable) {
    EXPECT_EQ("0", format_dns_ttl_units(0));
    EXPECT_EQ("59s", format_dns_ttl_units(59));
    EXPECT_EQ("1m", format_dns_ttl_units(60));
    EXPECT_EQ("5m", format_dns_ttl_units(300)); // dig 9.20 verified
    EXPECT_EQ("1h30m", format_dns_ttl_units(5400));
    EXPECT_EQ("1h1s", format_dns_ttl_units(3601));
    EXPECT_EQ("1d", format_dns_ttl_units(86400));
    EXPECT_EQ("1w", format_dns_ttl_units(604800));
    EXPECT_EQ("1d1h1m1s", format_dns_ttl_units(86400 + 3600 + 60 + 1));
}

// --- format_dns_ttl_verbose (SOA +multiline comments) -----------------------

TEST(FormatDnsTtlVerbose, ZeroIsZeroSeconds) {
    // dig 9.20 verified: BIND's `dns_ttl_totext(0, true, true)` is `0 seconds`.
    EXPECT_EQ("0 seconds", format_dns_ttl_verbose(0));
}

TEST(FormatDnsTtlVerbose, SubMinutePlural) {
    EXPECT_EQ("30 seconds", format_dns_ttl_verbose(30));
    EXPECT_EQ("1 second", format_dns_ttl_verbose(1));
}

TEST(FormatDnsTtlVerbose, MinutesSingularAndPlural) {
    EXPECT_EQ("1 minute", format_dns_ttl_verbose(60));    // dig: `; refresh (15 minutes)` etc
    EXPECT_EQ("15 minutes", format_dns_ttl_verbose(900)); // verified
    EXPECT_EQ("30 minutes", format_dns_ttl_verbose(1800));
    EXPECT_EQ("59 minutes 59 seconds", format_dns_ttl_verbose(3599));
}

TEST(FormatDnsTtlVerbose, HoursMinutesSecondsCombined) {
    // dig verified: `; refresh (2 hours 46 minutes 40 seconds)` for 10000s.
    EXPECT_EQ("2 hours 46 minutes 40 seconds", format_dns_ttl_verbose(10000));
    EXPECT_EQ("2 hours 46 minutes", format_dns_ttl_verbose(9960)); // secs=0 suppressed
    EXPECT_EQ("1 hour 30 minutes", format_dns_ttl_verbose(5400));
}

TEST(FormatDnsTtlVerbose, DaysAndWeeks) {
    EXPECT_EQ("1 day", format_dns_ttl_verbose(86400));
    EXPECT_EQ("1 week", format_dns_ttl_verbose(604800)); // dig: `; expire (1 week)`
    EXPECT_EQ("1 day 1 hour 1 minute 1 second", format_dns_ttl_verbose(86400 + 3600 + 60 + 1));
    EXPECT_EQ("2 weeks 3 days 4 hours 5 minutes 6 seconds",
            format_dns_ttl_verbose(2 * 604800 + 3 * 86400 + 4 * 3600 + 5 * 60 + 6));
}

// --- bug #10: EDNS option decoding (ECS / NSID / EDE) -----------------------

TEST(FormatEdnsOptionText, EcsDecode) {
    // family=1(IPv4), src=24(0x18), scope=24(0x18), addr=01 02 03 -> 1.2.3.0
    Bytes data{0x00, 0x01, 0x18, 0x18, 0x01, 0x02, 0x03};
    EXPECT_EQ("; CLIENT-SUBNET: 1.2.3.0/24/24\n", format_edns_option_text(8, data.data(), data.size()));
}

TEST(FormatEdnsOptionText, NsidDecode) {
    Bytes data{'p', 'o', 'p', ' '};
    EXPECT_EQ("; NSID: 706f7020 (\"pop \")\n", format_edns_option_text(3, data.data(), data.size()));
}

TEST(FormatEdnsOptionText, NsidEscapesQuoteAndBackslash) {
    // In the NSID quoted-string, `"` (0x22) and `\` (0x5C) must be
    // backslash-escaped (rendered as `\"` / `\\`) and non-printables use the
    // \DDD octal form — matching dig's presentation escaping. These two bytes
    // are otherwise printable, so the escape check must run BEFORE the
    // printable-range branch (a previous ordering emitted them raw).
    //
    // Data = '"' '\\' 0x01  ->  hex = "225c01"  ->  ascii = \" \\ \001
    // (in the quoted string these are the 8 chars: \ " \ \ \ 0 0 1).
    Bytes data{'"', '\\', 0x01};
    EXPECT_EQ("; NSID: 225c01 (\"\\\"\\\\\\001\")\n", format_edns_option_text(3, data.data(), data.size()));
}

TEST(FormatEdnsOptionText, EmptyNsidHasNoQuotes) {
    // dig 9.20 verified: an empty NSID option-data renders as just `; NSID:`
    // (no hex, no parenthetical quoted string — `("")` would previously be
    // printed by the historic code path that always emitted the quoted form).
    EXPECT_EQ("; NSID:\n", format_edns_option_text(3, nullptr, 0));
    Bytes empty{};
    EXPECT_EQ("; NSID:\n", format_edns_option_text(3, empty.data(), 0));
}

TEST(FormatEdnsOptionText, PaddingSemanticLabel) {
    // RFC 7830 Padding option (code 12): dig renders `; PADDING: (<N> bytes)`
    // where N is the option-data length (the padding octets are all zero by
    // definition). Verified against `dig 9.20 +ednsopt=12:000000000000000000...`
    // and against a responder returning an 11-byte padding option.
    std::vector<uint8_t> eleven_zeros(11, 0);
    EXPECT_EQ("; PADDING: (11 bytes)\n", format_edns_option_text(12, eleven_zeros.data(), 11));
    std::vector<uint8_t> four_zeros(4, 0);
    EXPECT_EQ("; PADDING: (4 bytes)\n", format_edns_option_text(12, four_zeros.data(), 4));
    EXPECT_EQ("; PADDING: (0 bytes)\n", format_edns_option_text(12, nullptr, 0));
}

TEST(FormatEdnsOptionText, EdeDecodeKnownNoText) {
    Bytes data{0x00, 0x14}; // info-code 20 = Not Authoritative
    EXPECT_EQ("; EDE: 20 (Not Authoritative)\n", format_edns_option_text(15, data.data(), data.size()));
}

TEST(FormatEdnsOptionText, EdeDecodeWithText) {
    Bytes data{0x00, 0x14, 'h', 'i'};
    EXPECT_EQ("; EDE: 20 (Not Authoritative): hi\n", format_edns_option_text(15, data.data(), data.size()));
}

TEST(FormatEdnsOptionText, CookieClientOnly) {
    // RFC 7873 COOKIE option (code 10): an 8-byte client cookie renders as
    // `; COOKIE: <hex>` (lowercase), mirroring `dig 9.20` which sends an 8-byte
    // client cookie by default and prints it back in the OPT PSEUDOSECTION.
    Bytes data{0x78, 0xc3, 0x49, 0x54, 0x61, 0x6f, 0xa0, 0x1d};
    EXPECT_EQ("; COOKIE: 78c34954616fa01d\n", format_edns_option_text(10, data.data(), data.size()));
}

TEST(FormatEdnsOptionText, CookieWithServerPart) {
    // A COOKIE option with a server cookie (16 bytes total: 8 client + 8 server)
    // renders as `; COOKIE: <client-hex> (<server-hex>)`.
    Bytes data{0x78, 0xc3, 0x49, 0x54, 0x61, 0x6f, 0xa0, 0x1d, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    EXPECT_EQ("; COOKIE: 78c34954616fa01d (0102030405060708)\n", format_edns_option_text(10, data.data(), data.size()));
}

TEST(FormatEdnsOptionText, CookieTooShortFallsBack) {
    // A COOKIE option with fewer than 8 bytes is malformed (RFC 7873 requires
    // an 8-byte client cookie); dig renders such a malformed option with the
    // generic `; \# <len> <hex>` form.
    Bytes data{0x12, 0x34};
    EXPECT_EQ("; \\# 2 1234\n", format_edns_option_text(10, data.data(), data.size()));
}

TEST(FormatEdnsOptionText, UnknownfallsBack) {
    Bytes data{0xAB};
    EXPECT_EQ("; \\# 1 ab\n", format_edns_option_text(99, data.data(), data.size()));
    EXPECT_EQ("; \\# 0 \n", format_edns_option_text(99, nullptr, 0));
}

} // namespace ag::adig::test
