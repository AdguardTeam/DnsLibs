// Unit tests for adig's pure CLI layer (adig_cli).
//
// This file is the test target registered in tools/adig/CMakeLists.txt. The
// pure functions under test live in adig_cli.{h,cpp}; the event-loop-dependent
// coroutine logic in adig.cpp is not covered here.
//
// Tests are added incrementally alongside each feature task; the placeholder
// suite was replaced as soon as the parser gained testable behavior.

#include <gtest/gtest.h>

#include <memory>
#include <string>
#include <vector>

#include "adig_cli.h"
#include "root_servers.h"

namespace ag::adig::test {

namespace {
// Helper: parse a argv vector and return the result.
ParseResult parse(std::vector<std::string> args) {
    // Keep the strings alive and mutable so we can hand `char *` pointers to
    // parse_args (which takes `char *argv[]`, not `const char *`) without a
    // const_cast.
    std::vector<std::string> owned = std::move(args);
    std::vector<char *> argv;
    argv.reserve(owned.size());
    for (std::string &a : owned) {
        argv.push_back(a.data());
    }
    return parse_args(static_cast<int>(argv.size()), argv.data());
}
} // namespace

// --- match_plus_keyword --------------------------------------------------

TEST(MatchPlusKeyword, ExactCanonical) {
    EXPECT_EQ("answer", match_plus_keyword("answer").canonical);
    EXPECT_EQ("short", match_plus_keyword("short").canonical);
    EXPECT_EQ("class", match_plus_keyword("class").canonical);
    EXPECT_EQ("all", match_plus_keyword("all").canonical);
}

TEST(MatchPlusKeyword, UnambiguousPrefix) {
    EXPECT_EQ("answer", match_plus_keyword("ans").canonical);
    EXPECT_EQ("short", match_plus_keyword("sh").canonical);
    EXPECT_EQ("additional", match_plus_keyword("add").canonical);
    EXPECT_EQ("authority", match_plus_keyword("auth").canonical);
}

TEST(MatchPlusKeyword, ExplicitAliasVc) {
    // +vc is the dig alias for +tcp.
    EXPECT_EQ("tcp", match_plus_keyword("vc").canonical);
}

TEST(MatchPlusKeyword, AmbiguousPrefixIsError) {
    KeywordMatch m = match_plus_keyword("a");
    EXPECT_TRUE(m.canonical.empty());
    // Every display flag whose canonical starts with 'a' must be listed.
    EXPECT_NE(std::string::npos, m.error.find("additional"));
    EXPECT_NE(std::string::npos, m.error.find("all"));
    EXPECT_NE(std::string::npos, m.error.find("answer"));
    EXPECT_NE(std::string::npos, m.error.find("authority"));
    EXPECT_NE(std::string::npos, m.error.find("ambiguous"));
}

TEST(MatchPlusKeyword, UnknownIsError) {
    KeywordMatch m = match_plus_keyword("xyz");
    EXPECT_TRUE(m.canonical.empty());
    EXPECT_NE(std::string::npos, m.error.find("unknown option"));
    EXPECT_NE(std::string::npos, m.error.find("xyz"));
}

// --- display-flag toggling via parse_args --------------------------------

TEST(ParseDisplayFlags, NoAllClearsEveryFlag) {
    ParseResult r = parse({"adig", "example.com", "+noall"});
    ASSERT_TRUE(r.error.empty()) << r.error;
    const DisplayFlags &d = r.opts.display;
    EXPECT_FALSE(d.cmd);
    EXPECT_FALSE(d.comments);
    EXPECT_FALSE(d.question);
    EXPECT_FALSE(d.answer);
    EXPECT_FALSE(d.authority);
    EXPECT_FALSE(d.additional);
    EXPECT_FALSE(d.stats);
    EXPECT_FALSE(d.multiline);
    EXPECT_FALSE(d.ttlid);
    EXPECT_FALSE(d.cls);
}

TEST(ParseDisplayFlags, AllSetsEveryFlag) {
    // +noall then +all: every flag ends up true, including the ones that
    // default to false (multiline).
    ParseResult r = parse({"adig", "example.com", "+noall", "+all"});
    ASSERT_TRUE(r.error.empty()) << r.error;
    const DisplayFlags &d = r.opts.display;
    EXPECT_TRUE(d.cmd);
    EXPECT_TRUE(d.comments);
    EXPECT_TRUE(d.question);
    EXPECT_TRUE(d.answer);
    EXPECT_TRUE(d.authority);
    EXPECT_TRUE(d.additional);
    EXPECT_TRUE(d.stats);
    EXPECT_TRUE(d.multiline);
    EXPECT_TRUE(d.ttlid);
    EXPECT_TRUE(d.cls);
}

TEST(ParseDisplayFlags, NoAnswerOnlyClearsAnswer) {
    ParseResult r = parse({"adig", "example.com", "+noanswer"});
    ASSERT_TRUE(r.error.empty()) << r.error;
    const DisplayFlags &d = r.opts.display;
    EXPECT_FALSE(d.answer);
    // Untouched flags keep their defaults.
    EXPECT_TRUE(d.cmd);
    EXPECT_TRUE(d.authority);
    EXPECT_TRUE(d.stats);
    EXPECT_FALSE(d.multiline);
}

TEST(ParseDisplayFlags, NoCmdOnlyClearsCmd) {
    ParseResult r = parse({"adig", "example.com", "+nocmd"});
    ASSERT_TRUE(r.error.empty()) << r.error;
    EXPECT_FALSE(r.opts.display.cmd);
    EXPECT_TRUE(r.opts.display.answer);
}

TEST(ParseDisplayFlags, NoAllThenSelectiveReenable) {
    ParseResult r = parse({"adig", "example.com", "+noall", "+answer", "+authority"});
    ASSERT_TRUE(r.error.empty()) << r.error;
    const DisplayFlags &d = r.opts.display;
    EXPECT_TRUE(d.answer);
    EXPECT_TRUE(d.authority);
    EXPECT_FALSE(d.cmd);
    EXPECT_FALSE(d.question);
    EXPECT_FALSE(d.stats);
    EXPECT_FALSE(d.additional);
    EXPECT_FALSE(d.multiline);
}

// --- existing boolean options through the new mechanism -------------------

TEST(ParseArgs, AbbreviatedShortResolves) {
    ParseResult r = parse({"adig", "example.com", "+sh"});
    ASSERT_TRUE(r.error.empty()) << r.error;
    EXPECT_TRUE(r.opts.short_output);
}

TEST(ParseArgs, NoTcpClearsForceTcp) {
    ParseResult r = parse({"adig", "example.com", "+notcp"});
    ASSERT_TRUE(r.error.empty()) << r.error;
    EXPECT_FALSE(r.opts.force_tcp);
}

TEST(ParseArgs, ValueOptionDoesNotSupportNoForm) {
    ParseResult r = parse({"adig", "example.com", "+notimeout=5"});
    EXPECT_FALSE(r.error.empty());
    EXPECT_NE(std::string::npos, r.error.find("no"));
}

// --- +recurse / +norecurse ------------------------------------------------

TEST(ParseRecurse, DefaultsOn) {
    ParseResult r = parse({"adig", "example.com"});
    ASSERT_TRUE(r.error.empty()) << r.error;
    EXPECT_TRUE(r.opts.recurse);
}

TEST(ParseRecurse, NoRecurseClears) {
    ParseResult r = parse({"adig", "example.com", "+norecurse"});
    ASSERT_TRUE(r.error.empty()) << r.error;
    EXPECT_FALSE(r.opts.recurse);
}

TEST(ParseRecurse, AbbreviationResolves) {
    EXPECT_TRUE(parse({"adig", "example.com", "+rec"}).opts.recurse);
    EXPECT_FALSE(parse({"adig", "example.com", "+norec"}).opts.recurse);
}

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

// --- apply_dns_flags (DNSSEC DO bit) --------------------------------------

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

// --- +dnssec / +do parsing ------------------------------------------------

TEST(MatchPlusKeyword, ExplicitAliasDo) {
    EXPECT_EQ("dnssec", match_plus_keyword("do").canonical);
    EXPECT_EQ("dnssec", match_plus_keyword("dnssec").canonical);
    EXPECT_EQ("dnssec", match_plus_keyword("dn").canonical); // unambiguous prefix
}

TEST(ParseDnssec, KeywordAliasAndNoForm) {
    EXPECT_TRUE(parse({"adig", "example.com", "+dnssec"}).opts.dnssec);
    EXPECT_TRUE(parse({"adig", "example.com", "+do"}).opts.dnssec);
    EXPECT_FALSE(parse({"adig", "example.com", "+nodnssec"}).opts.dnssec);
    EXPECT_FALSE(parse({"adig", "example.com", "+nodo"}).opts.dnssec);
}

// --- +cdflag / +cd (Checking Disabled) -----------------------------------

TEST(MatchPlusKeyword, ExplicitAliasCd) {
    EXPECT_EQ("cdflag", match_plus_keyword("cd").canonical);
    EXPECT_EQ("cdflag", match_plus_keyword("cdflag").canonical);
    EXPECT_EQ("cdflag", match_plus_keyword("cdf").canonical); // unambiguous prefix
}

TEST(ParseCdflag, KeywordAliasAndNoForm) {
    EXPECT_TRUE(parse({"adig", "example.com", "+cdflag"}).opts.cd);
    EXPECT_TRUE(parse({"adig", "example.com", "+cd"}).opts.cd);
    EXPECT_FALSE(parse({"adig", "example.com", "+nocdflag"}).opts.cd);
    EXPECT_FALSE(parse({"adig", "example.com", "+nocd"}).opts.cd);
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

// --- -4 / -6 (IPv4-only) --------------------------------------------------

TEST(ParseIpv4Only, DefaultsFalse) {
    ParseResult r = parse({"adig", "example.com"});
    ASSERT_TRUE(r.error.empty()) << r.error;
    EXPECT_FALSE(r.opts.ipv4_only);
}

TEST(ParseIpv4Only, FlagSets) {
    ParseResult r = parse({"adig", "example.com", "-4"});
    ASSERT_TRUE(r.error.empty()) << r.error;
    EXPECT_TRUE(r.opts.ipv4_only);
}

TEST(ParseIpv4Only, SixIsUnsupported) {
    ParseResult r = parse({"adig", "example.com", "-6"});
    EXPECT_FALSE(r.error.empty());
    EXPECT_NE(std::string::npos, r.error.find("-6"));
}

// --- +qr (print query) / prefix ambiguity with question -------------------

TEST(ParseQr, FlagToggles) {
    EXPECT_FALSE(parse({"adig", "example.com"}).opts.print_query);
    EXPECT_TRUE(parse({"adig", "example.com", "+qr"}).opts.print_query);
    EXPECT_FALSE(parse({"adig", "example.com", "+noqr"}).opts.print_query);
}

TEST(MatchPlusKeyword, QPrefixIsAmbiguous) {
    // +q matches both `qr` and `question`.
    KeywordMatch m = match_plus_keyword("q");
    EXPECT_TRUE(m.canonical.empty());
    EXPECT_NE(std::string::npos, m.error.find("qr"));
    EXPECT_NE(std::string::npos, m.error.find("question"));
}

// --- -v / --version -------------------------------------------------------

TEST(ParseVersion, FlagsRequestVersion) {
    EXPECT_TRUE(parse({"adig", "-v"}).version_requested);
    EXPECT_TRUE(parse({"adig", "--version"}).version_requested);
    EXPECT_FALSE(parse({"adig", "example.com"}).version_requested);
}

// --- encode_ecs_option (RFC 7871, byte-exact) ----------------------------

namespace {
using Bytes = std::vector<uint8_t>;
} // namespace

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

// --- +subnet= parsing -----------------------------------------------------

TEST(ParseSubnet, AddrPrefix) {
    ParseResult r = parse({"adig", "example.com", "+subnet=1.2.3.4/24"});
    ASSERT_TRUE(r.error.empty()) << r.error;
    EXPECT_TRUE(r.opts.subnet.enabled);
    EXPECT_EQ("1.2.3.4", r.opts.subnet.addr);
    EXPECT_EQ(24u, r.opts.subnet.src_prefix);
}

TEST(ParseSubnet, Ipv6Prefix) {
    ParseResult r = parse({"adig", "example.com", "+subnet=::1/64"});
    ASSERT_TRUE(r.error.empty()) << r.error;
    EXPECT_EQ("::1", r.opts.subnet.addr);
    EXPECT_EQ(64u, r.opts.subnet.src_prefix);
}

TEST(ParseSubnet, ZeroPrefixSentinel) {
    ParseResult r = parse({"adig", "example.com", "+subnet=0.0.0.0/0"});
    ASSERT_TRUE(r.error.empty()) << r.error;
    EXPECT_EQ(0u, r.opts.subnet.src_prefix);
}

TEST(ParseSubnet, BareIpDefaultsToFullPrefix) {
    EXPECT_EQ(32u, parse({"adig", "example.com", "+subnet=1.2.3.4"}).opts.subnet.src_prefix);
    EXPECT_EQ(128u, parse({"adig", "example.com", "+subnet=::1"}).opts.subnet.src_prefix);
}

TEST(ParseSubnet, InvalidPrefixOutOfRange) {
    EXPECT_FALSE(parse({"adig", "example.com", "+subnet=1.2.3.4/40"}).error.empty());
}

TEST(ParseSubnet, InvalidAddress) {
    EXPECT_FALSE(parse({"adig", "example.com", "+subnet=example.com/24"}).error.empty());
}

TEST(ApplyDnsFlags, SubnetAttachesEcsOption) {
    ldns_pkt_ptr q = make_query("example.com", LDNS_RR_TYPE_A, true);
    ASSERT_NE(nullptr, q.get());
    CliOptions opts;
    opts.subnet = {.enabled = true, .addr = "1.2.3.4", .src_prefix = 24};
    apply_dns_flags(q.get(), opts);
    ldns_rdf *data = ldns_pkt_edns_data(q.get());
    ASSERT_NE(nullptr, data);
    const uint8_t *bytes = ldns_rdf_data(data);
    size_t sz = ldns_rdf_size(data);
    Bytes actual(bytes, bytes + sz);
    EXPECT_EQ((Bytes{0x00, 0x08, 0x00, 0x07, 0x00, 0x01, 0x18, 0x00, 0x01, 0x02, 0x03}), actual);
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

// --- -x reverse-lookup flow -----------------------------------------------

TEST(ParseReverse, SetsNameTypeAndFlag) {
    ParseResult r = parse({"adig", "-x", "8.8.8.8"});
    ASSERT_TRUE(r.error.empty()) << r.error;
    EXPECT_EQ("8.8.8.8.in-addr.arpa.", r.opts.name);
    EXPECT_EQ(LDNS_RR_TYPE_PTR, r.opts.rr_type);
    EXPECT_TRUE(r.opts.reverse);
}

TEST(ParseReverse, MissingAddressIsError) {
    ParseResult r = parse({"adig", "-x"});
    EXPECT_FALSE(r.error.empty());
    EXPECT_NE(std::string::npos, r.error.find("address"));
}

TEST(ParseReverse, InvalidAddressIsError) {
    ParseResult r = parse({"adig", "-x", "999.1.1.1"});
    EXPECT_FALSE(r.error.empty());
    EXPECT_NE(std::string::npos, r.error.find("invalid address"));
}

TEST(ParseReverse, RejectsPositionalAfterX) {
    ParseResult r = parse({"adig", "-x", "8.8.8.8", "example.com"});
    EXPECT_FALSE(r.error.empty());
    EXPECT_NE(std::string::npos, r.error.find("-x"));
}

TEST(ParseReverse, RejectsXAfterPositionalName) {
    ParseResult r = parse({"adig", "example.com", "-x", "8.8.8.8"});
    EXPECT_FALSE(r.error.empty());
    EXPECT_NE(std::string::npos, r.error.find("-x"));
}

TEST(ParseReverse, RejectsXWithType) {
    ParseResult r = parse({"adig", "example.com", "A", "-x", "8.8.8.8"});
    EXPECT_FALSE(r.error.empty());
    EXPECT_NE(std::string::npos, r.error.find("-x"));
}

// --- default server (pure-layer contract) ---------------------------------
//
// The pure parser must NOT invent a default @server: an empty opts.server
// signals main() to resolve the system default DNS via the upstream module's
// SystemUpstream (system://) on Apple/Android, else DEFAULT_SERVER. The
// actual default resolution lives in adig.cpp (alongside run_query/run_trace,
// which are not unit-tested here); here we only guard the contract that the
// default is applied outside the pure layer.

TEST(ParseArgs, NoServerLeavesServerEmpty) {
    ParseResult r = parse({"adig", "example.com"});
    ASSERT_TRUE(r.error.empty()) << r.error;
    EXPECT_TRUE(r.opts.server.empty());
}

TEST(ParseArgs, ExplicitServerIsKept) {
    ParseResult r = parse({"adig", "@8.8.8.8", "example.com"});
    ASSERT_TRUE(r.error.empty()) << r.error;
    EXPECT_EQ("8.8.8.8", r.opts.server);
}

// --- format_packet_dig (dig-style output) --------------------------------

namespace {

// Build a simple A query for format_packet_dig tests.
ldns_pkt_ptr make_test_query() {
    return make_query("example.com", LDNS_RR_TYPE_A, true);
}

// Check that `haystack` contains `needle`.
bool contains(std::string_view haystack, std::string_view needle) {
    return haystack.find(needle) != std::string::npos;
}

} // namespace

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
    EXPECT_TRUE(contains(out, "MSG SIZE  sent:"));
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
    EXPECT_TRUE(contains(out, ";example.com.\tIN\tA"));
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
    // adig) emits just the RRs without the `;; ... SECTION:` headers.
    EXPECT_FALSE(contains(out, "QUESTION SECTION:"));
    EXPECT_FALSE(contains(out, "ANSWER SECTION:"));
    // The question RR is still present (gated by +question, not +comments).
    EXPECT_TRUE(contains(out, ";example.com.\tIN\tA"));
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

// --- root_servers.h (generated IANA root hints) ---------------------------
//
// These tests guard the checked-in generated table (see
// `make generate_root_hints`). They run entirely offline — the IANA fetch
// happens only in the generator script, never in tests.

TEST(RootHints, HasThirteenServersIdsAToM) {
    EXPECT_EQ(std::size(root_hints::ROOT_SERVERS), 13u);
    char expected = 'a';
    for (const root_hints::RootServer &s : root_hints::ROOT_SERVERS) {
        EXPECT_EQ(s.id, expected) << "root server id out of order at index " << (expected - 'a');
        EXPECT_FALSE(s.ip.empty());
        ++expected;
    }
}

TEST(RootHints, GlueAddressesAreValidIpv4) {
    for (const root_hints::RootServer &s : root_hints::ROOT_SERVERS) {
        const std::string ip(s.ip);
        std::unique_ptr<ldns_rdf, void (*)(ldns_rdf *)> rdf(
                ldns_rdf_new_frm_str(LDNS_RDF_TYPE_A, ip.c_str()), &ldns_rdf_deep_free);
        EXPECT_NE(rdf.get(), nullptr) << "invalid IPv4 glue for root server '" << s.id << "': " << ip;
    }
}

// --- apply_trace_display_defaults (dig +trace display flag overrides) ------
//
// `dig +trace` toggles `comments`, `question`, `stats` off (so the per-hop
// output collapses to plain RRs followed by the "Received ... bytes from ..."
// footer). Section toggles stay at their default (on).

TEST(ApplyTraceDisplayDefaults, ClearsCommentsQuestionStats) {
    DisplayFlags df; // defaults: every flag is on, multiline is off
    apply_trace_display_defaults(df);
    EXPECT_FALSE(df.comments);
    EXPECT_FALSE(df.question);
    EXPECT_FALSE(df.stats);
    // The data-carrying sections stay on so dig prints the per-hop RRs.
    EXPECT_TRUE(df.answer);
    EXPECT_TRUE(df.authority);
    EXPECT_TRUE(df.additional);
    EXPECT_TRUE(df.cmd);
    // Multiline / ttlid / cls are untouched by the trace override.
    EXPECT_FALSE(df.multiline);
    EXPECT_TRUE(df.ttlid);
    EXPECT_TRUE(df.cls);
}

TEST(ApplyTraceDisplayDefaults, DoesNotTouchMultilineTtlidClass) {
    DisplayFlags df;
    df.multiline = true;
    df.ttlid = false;
    df.cls = false;
    apply_trace_display_defaults(df);
    EXPECT_TRUE(df.multiline);
    EXPECT_FALSE(df.ttlid);
    EXPECT_FALSE(df.cls);
}

// --- +trace parsing (display defaults applied in order) -------------------
//
// `dig +trace`'s display-flag overrides apply at the point `+trace` is seen;
// any display flag mentioned AFTER `+trace` still wins (dig parses in order,
// second match takes effect). A display flag before `+trace` is overwritten
// by the trace defaults.

TEST(ParseTrace, SetsTraceAndAppliesDefaults) {
    ParseResult r = parse({"adig", "example.com", "+trace"});
    ASSERT_TRUE(r.error.empty()) << r.error;
    EXPECT_TRUE(r.opts.trace);
    EXPECT_FALSE(r.opts.display.comments);
    EXPECT_FALSE(r.opts.display.question);
    EXPECT_FALSE(r.opts.display.stats);
}

TEST(ParseTrace, DefaultsOffAndAbbreviationMatch) {
    ParseResult r = parse({"adig", "example.com"});
    ASSERT_TRUE(r.error.empty()) << r.error;
    EXPECT_FALSE(r.opts.trace);
    // +tra / +tr should resolve to the unambiguous +trace prefix.
    EXPECT_TRUE(parse({"adig", "example.com", "+tra"}).opts.trace);
    EXPECT_TRUE(parse({"adig", "example.com", "+tr"}).opts.trace);
    EXPECT_FALSE(parse({"adig", "example.com", "+notrace"}).opts.trace);
}

TEST(ParseTrace, LaterCommentsOverridesTraceDefault) {
    // `+trace +comments`: trace defaults apply (comments=false), then the
    // later `+comments` re-enables comments.
    ParseResult r = parse({"adig", "example.com", "+trace", "+comments"});
    ASSERT_TRUE(r.error.empty()) << r.error;
    EXPECT_TRUE(r.opts.trace);
    EXPECT_TRUE(r.opts.display.comments);
    // Other trace defaults survive (only comments was re-enabled).
    EXPECT_FALSE(r.opts.display.question);
    EXPECT_FALSE(r.opts.display.stats);
}

TEST(ParseTrace, EarlierCommentsOverriddenByTrace) {
    // `+comments +trace`: comments=true is set first, then +trace's defaults
    // overwrite it back to false (mirrors dig's order-sensitive semantics).
    ParseResult r = parse({"adig", "example.com", "+comments", "+trace"});
    ASSERT_TRUE(r.error.empty()) << r.error;
    EXPECT_TRUE(r.opts.trace);
    EXPECT_FALSE(r.opts.display.comments);
    EXPECT_FALSE(r.opts.display.stats);
}

TEST(ParseTrace, LaterStatsOverridesTraceDefault) {
    ParseResult r = parse({"adig", "example.com", "+trace", "+stats"});
    ASSERT_TRUE(r.error.empty()) << r.error;
    EXPECT_TRUE(r.opts.trace);
    EXPECT_TRUE(r.opts.display.stats);
    // Comments/question still suppressed by the trace defaults.
    EXPECT_FALSE(r.opts.display.comments);
    EXPECT_FALSE(r.opts.display.question);
}

TEST(ParseTrace, AllAfterTraceReenablesEverything) {
    ParseResult r = parse({"adig", "example.com", "+trace", "+all"});
    ASSERT_TRUE(r.error.empty()) << r.error;
    EXPECT_TRUE(r.opts.trace);
    // +all wins: every display flag ends up on (including the trace defaults).
    const DisplayFlags &d = r.opts.display;
    EXPECT_TRUE(d.comments);
    EXPECT_TRUE(d.question);
    EXPECT_TRUE(d.stats);
    EXPECT_TRUE(d.answer);
    EXPECT_TRUE(d.authority);
    EXPECT_TRUE(d.additional);
    EXPECT_TRUE(d.multiline);
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
// `Query time / SERVER (as IP#53(name) (UDP)) / MSG SIZE` block.

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

} // namespace ag::adig::test
