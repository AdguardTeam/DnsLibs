// Unit tests for adig's pure CLI layer — argument parsing & CLI transforms.
//
// This is one of the split test translation units registered in
// tools/adig/CMakeLists.txt. It covers parse_args(), match_plus_keyword(), the
// display-flag helpers and the small pure decision/rewrite helpers
// (cmd_banner_enabled / apply_force_tcp / apply_port /
// apply_trace_display_defaults). The EDNS/IP tests live in
// test_adig_cli_edns.cpp and the packet/format tests in
// test_adig_cli_packet.cpp. Shared helpers are in
// test_adig_cli_helpers.h.

#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "adig_cli.h"
#include "root_servers.h"
#include "test_adig_cli_helpers.h"

namespace ag::adig::test {

// --- match_plus_keyword --------------------------------------------------

TEST(MatchPlusKeyword, ExactCanonical) {
    EXPECT_EQ("answer", match_plus_keyword("answer").canonical);
    EXPECT_EQ("short", match_plus_keyword("short").canonical);
    EXPECT_EQ("class", match_plus_keyword("class").canonical);
    EXPECT_EQ("all", match_plus_keyword("all").canonical);
}

TEST(MatchPlusKeyword, UnambiguousPrefix) {
    EXPECT_EQ("answer", match_plus_keyword("ans").canonical);
    // `+sh` would be ambiguous now (short vs showsearch) — verified against
    // `dig 9.20` (`dig +sh` -> "Invalid option: +sh"). Use `+shor` instead.
    EXPECT_EQ("short", match_plus_keyword("shor").canonical);
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

TEST(MatchPlusKeyword, ExplicitAliasDo) {
    EXPECT_EQ("dnssec", match_plus_keyword("do").canonical);
    EXPECT_EQ("dnssec", match_plus_keyword("dnssec").canonical);
    EXPECT_EQ("dnssec", match_plus_keyword("dn").canonical); // unambiguous prefix
}

TEST(MatchPlusKeyword, EdnsKeyword) {
    EXPECT_EQ("edns", match_plus_keyword("edns").canonical);
    // `+ed` / `+edn` are now ambiguous (edns vs ednsflags), verified against
    // `dig 9.20` (`dig +ed` -> "Invalid option: +ed"). `+ednsf` resolves to
    // ednsflags instead.
    EXPECT_TRUE(match_plus_keyword("ed").canonical.empty());
    EXPECT_NE(std::string::npos, match_plus_keyword("ed").error.find("edns"));
    EXPECT_NE(std::string::npos, match_plus_keyword("ed").error.find("ednsflags"));
    EXPECT_TRUE(match_plus_keyword("edn").canonical.empty());
    EXPECT_EQ("ednsflags", match_plus_keyword("ednsf").canonical);
}

TEST(MatchPlusKeyword, ExplicitAliasCd) {
    EXPECT_EQ("cdflag", match_plus_keyword("cd").canonical);
    EXPECT_EQ("cdflag", match_plus_keyword("cdflag").canonical);
    EXPECT_EQ("cdflag", match_plus_keyword("cdf").canonical); // unambiguous prefix
}

TEST(MatchPlusKeyword, QPrefixIsAmbiguous) {
    // +q matches both `qr` and `question`.
    KeywordMatch m = match_plus_keyword("q");
    EXPECT_TRUE(m.canonical.empty());
    EXPECT_NE(std::string::npos, m.error.find("qr"));
    EXPECT_NE(std::string::npos, m.error.find("question"));
}

TEST(MatchPlusKeyword, ExplicitAliasRd) {
    EXPECT_EQ("recurse", match_plus_keyword("rd").canonical);
    EXPECT_EQ("recurse", match_plus_keyword("rdflag").canonical);
    EXPECT_EQ("recurse", match_plus_keyword("recurse").canonical);
}

TEST(MatchPlusKeyword, EdnsoptKeyword) {
    EXPECT_EQ("ednsopt", match_plus_keyword("ednsopt").canonical);
    // `+ednso` is the shortest unambiguous prefix for `ednsopt`.
    EXPECT_EQ("ednsopt", match_plus_keyword("ednso").canonical);
    // `+ednsf` still resolves to `ednsflags` (only candidate).
    EXPECT_EQ("ednsflags", match_plus_keyword("ednsf").canonical);
}

TEST(MatchPlusKeyword, EdnsPrefixStillAmbiguous) {
    // Adding `ednsopt` keeps `+ed` / `+edn` ambiguous (edns / ednsflags /
    // ednsopt) — verified against the existing EdnsKeyword expectations.
    KeywordMatch m = match_plus_keyword("ed");
    EXPECT_TRUE(m.canonical.empty());
    EXPECT_NE(std::string::npos, m.error.find("edns"));
    EXPECT_NE(std::string::npos, m.error.find("ednsflags"));
    EXPECT_NE(std::string::npos, m.error.find("ednsopt"));
    EXPECT_TRUE(match_plus_keyword("edn").canonical.empty());
}

// --- display-flag toggling via parse_args --------------------------------

TEST(ParseDisplayFlags, NoAllClearsEverySectionFlag) {
    // `dig +noall` toggles only the section-level flags; the field-level flags
    // (ttlid / cls) keep their defaults (on), and multiline stays off (its
    // default). Verified against `dig 9.20`.
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
    // Field-level flags are NOT part of `+all`/`+noall`: they keep defaults.
    EXPECT_TRUE(d.ttlid);
    EXPECT_TRUE(d.cls);
}

TEST(ParseDisplayFlags, AllSetsEverySectionFlag) {
    // +noall then +all: every section flag ends up true. The field-level flags
    // (ttlid / cls) keep their (default-on) values; multiline keeps its
    // (default-off) value — `dig +all` does not enable multiline.
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
    EXPECT_FALSE(d.multiline);
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

TEST(ParseDisplayFlags, NoAllAnswerKeepsTtlAndClass) {
    // Regression: `+noall` must not toggle the field-level flags, so
    // `+noall +answer` still shows TTL and class (matching `dig`). Previously
    // `+noall` cleared `ttlid`/`cls` and `+answer` did not restore them, so the
    // printed RRs lost both fields.
    ParseResult r = parse({"adig", "example.com", "+noall", "+answer"});
    ASSERT_TRUE(r.error.empty()) << r.error;
    const DisplayFlags &d = r.opts.display;
    EXPECT_TRUE(d.answer);
    EXPECT_TRUE(d.ttlid);
    EXPECT_TRUE(d.cls);
}

TEST(ParseDisplayFlags, NoAllPreservesExplicitlyClearedFieldFlags) {
    // `dig +nottlid +noall +answer` omits the TTL: `+nottlid` clears it and
    // `+noall` does not restore it. Symmetric check for `+noclass`.
    EXPECT_FALSE(parse({"adig", "example.com", "+nottlid", "+noall", "+answer"}).opts.display.ttlid);
    EXPECT_TRUE(parse({"adig", "example.com", "+nottlid", "+noall", "+answer"}).opts.display.cls);
    EXPECT_TRUE(parse({"adig", "example.com", "+noclass", "+noall", "+answer"}).opts.display.ttlid);
    EXPECT_FALSE(parse({"adig", "example.com", "+noclass", "+noall", "+answer"}).opts.display.cls);
}

TEST(ParseDisplayFlags, AllDoesNotTouchFieldFlags) {
    // `dig +nottlid +all` still omits the TTL, and `dig +noclass +all` still
    // omits the class: `+all` does not toggle the field-level flags.
    EXPECT_FALSE(parse({"adig", "example.com", "+nottlid", "+all"}).opts.display.ttlid);
    EXPECT_FALSE(parse({"adig", "example.com", "+noclass", "+all"}).opts.display.cls);
    // `+all` does not enable multiline either (mirrors `dig +all`).
    EXPECT_FALSE(parse({"adig", "example.com", "+all"}).opts.display.multiline);
    EXPECT_TRUE(parse({"adig", "example.com", "+multiline", "+all"}).opts.display.multiline);
}

// --- cmd_banner_enabled (+short suppresses the +cmd banner) ----------------
//
// `dig`'s `; <<>> DiG ... <<>>` / `;; global options: +cmd` banner is gated on
// `+cmd`, but `+short` suppresses it unconditionally — even `+short +cmd`
// prints no banner — so short output is RDATA-only. Verified against `dig 9.20`.

TEST(CmdBannerEnabled, DefaultOn) {
    CliOptions opts;
    EXPECT_TRUE(cmd_banner_enabled(opts));
}

TEST(CmdBannerEnabled, ShortSuppressesBanner) {
    CliOptions opts;
    opts.short_output = true;
    EXPECT_FALSE(cmd_banner_enabled(opts));
}

TEST(CmdBannerEnabled, ShortWinsOverCmd) {
    // `+short +cmd`: short wins, no banner (mirrors `dig +short +cmd`).
    CliOptions opts;
    opts.short_output = true;
    opts.display.cmd = true; // explicitly enabled by +cmd
    EXPECT_FALSE(cmd_banner_enabled(opts));
}

TEST(CmdBannerEnabled, NoCmdSuppressesBanner) {
    CliOptions opts;
    opts.display.cmd = false; // +nocmd
    EXPECT_FALSE(cmd_banner_enabled(opts));
}

// --- existing boolean options through the new mechanism -------------------

TEST(ParseArgs, AbbreviatedShortResolves) {
    // `+sh` is ambiguous now (short vs showsearch), so it must error — verified
    // against `dig 9.20` (`dig +sh` -> "Invalid option: +sh"). `+shor` is the
    // shortest unambiguous prefix for `+short`.
    ParseResult r = parse({"adig", "example.com", "+sh"});
    EXPECT_FALSE(r.error.empty());
    EXPECT_TRUE(parse({"adig", "example.com", "+shor"}).opts.short_output);
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

TEST(ParseRecurse, RdAliasAndNoForm) {
    EXPECT_TRUE(parse({"adig", "example.com", "+rd"}).opts.recurse);
    EXPECT_TRUE(parse({"adig", "example.com", "+rdflag"}).opts.recurse);
    EXPECT_FALSE(parse({"adig", "example.com", "+nord"}).opts.recurse);
    EXPECT_FALSE(parse({"adig", "example.com", "+nordflag"}).opts.recurse);
}

// --- +dnssec / +do parsing ------------------------------------------------

TEST(ParseDnssec, KeywordAliasAndNoForm) {
    EXPECT_TRUE(parse({"adig", "example.com", "+dnssec"}).opts.dnssec);
    EXPECT_TRUE(parse({"adig", "example.com", "+do"}).opts.dnssec);
    EXPECT_FALSE(parse({"adig", "example.com", "+nodnssec"}).opts.dnssec);
    EXPECT_FALSE(parse({"adig", "example.com", "+nodo"}).opts.dnssec);
}

// --- +edns / +noedns (EDNS OPT RR) ---------------------------------------
//
// `dig` sends EDNS by default (an OPT RR carrying version 0 and a UDP payload
// size). `+edns[=N]` explicitly enables it (optionally advertising version N,
// 0..255); `+noedns` disables the default OPT RR. `+dnssec` (DO bit) and
// `+subnet` (ECS option) still force an OPT RR even under `+noedns`, since
// those live inside the OPT record — verified against `dig 9.20` via its
// `+qr` query echo.

TEST(ParseEdns, DefaultsOn) {
    // No +edns on the command line: EDNS is on by default with version 0,
    // matching `dig` (a plain `dig example.com` sends an OPT RR).
    ParseResult r = parse({"adig", "example.com"});
    ASSERT_TRUE(r.error.empty()) << r.error;
    EXPECT_TRUE(r.opts.edns);
    EXPECT_EQ(0u, r.opts.edns_version);
}

TEST(ParseEdns, BareEdnsEnablesVersion0) {
    ParseResult r = parse({"adig", "example.com", "+edns"});
    ASSERT_TRUE(r.error.empty()) << r.error;
    EXPECT_TRUE(r.opts.edns);
    EXPECT_EQ(0u, r.opts.edns_version);
}

TEST(ParseEdns, EdnsVersion0Explicit) {
    // `+edns=0` is equivalent to `+edns` (the dig default).
    ParseResult r = parse({"adig", "example.com", "+edns=0"});
    ASSERT_TRUE(r.error.empty()) << r.error;
    EXPECT_TRUE(r.opts.edns);
    EXPECT_EQ(0u, r.opts.edns_version);
}

TEST(ParseEdns, EdnsVersionN) {
    EXPECT_EQ(1u, parse({"adig", "example.com", "+edns=1"}).opts.edns_version);
    EXPECT_EQ(255u, parse({"adig", "example.com", "+edns=255"}).opts.edns_version);
}

TEST(ParseEdns, EdnsVersionEnablesEdns) {
    // `+edns=N` must also turn EDNS on (not just set the version).
    EXPECT_TRUE(parse({"adig", "example.com", "+edns=1"}).opts.edns);
}

TEST(ParseEdns, NoEdnsDisables) {
    ParseResult r = parse({"adig", "example.com", "+noedns"});
    ASSERT_TRUE(r.error.empty()) << r.error;
    EXPECT_FALSE(r.opts.edns);
}

TEST(ParseEdns, NoEdnsRejectsValue) {
    // `+noedns` does not take a value (it is a pure toggle).
    EXPECT_FALSE(parse({"adig", "example.com", "+noedns=0"}).error.empty());
    EXPECT_FALSE(parse({"adig", "example.com", "+noedns=1"}).error.empty());
}

TEST(ParseEdns, InvalidVersionRejected) {
    EXPECT_FALSE(parse({"adig", "example.com", "+edns=256"}).error.empty());
    EXPECT_FALSE(parse({"adig", "example.com", "+edns=abc"}).error.empty());
    EXPECT_FALSE(parse({"adig", "example.com", "+edns=-1"}).error.empty());
    EXPECT_FALSE(parse({"adig", "example.com", "+edns=0x0"}).error.empty());
}

TEST(ParseEdns, AbbreviationResolves) {
    // `+ed` / `+noed` are ambiguous now (edns vs ednsflags) — verified against
    // `dig 9.20` (`dig +ed` / `dig +noed` both error). Use the full forms.
    EXPECT_TRUE(parse({"adig", "example.com", "+edns"}).opts.edns);
    EXPECT_FALSE(parse({"adig", "example.com", "+noedns"}).opts.edns);
    EXPECT_FALSE(parse({"adig", "example.com", "+ed"}).error.empty());
    EXPECT_FALSE(parse({"adig", "example.com", "+noed"}).error.empty());
}

TEST(ParseEdns, OrderSensitiveToggle) {
    // Mirrors dig's order-sensitive semantics: the last +edns/+noedns wins.
    EXPECT_FALSE(parse({"adig", "example.com", "+edns", "+noedns"}).opts.edns);
    EXPECT_TRUE(parse({"adig", "example.com", "+noedns", "+edns"}).opts.edns);
    // A later +edns=N after +noedns re-enables EDNS with version N.
    ParseResult r = parse({"adig", "example.com", "+noedns", "+edns=1"});
    ASSERT_TRUE(r.error.empty()) << r.error;
    EXPECT_TRUE(r.opts.edns);
    EXPECT_EQ(1u, r.opts.edns_version);
}

// --- +cdflag / +cd (Checking Disabled) -----------------------------------

TEST(ParseCdflag, KeywordAliasAndNoForm) {
    EXPECT_TRUE(parse({"adig", "example.com", "+cdflag"}).opts.cd);
    EXPECT_TRUE(parse({"adig", "example.com", "+cd"}).opts.cd);
    EXPECT_FALSE(parse({"adig", "example.com", "+nocdflag"}).opts.cd);
    EXPECT_FALSE(parse({"adig", "example.com", "+nocd"}).opts.cd);
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

// --- -v / --version -------------------------------------------------------

TEST(ParseVersion, FlagsRequestVersion) {
    EXPECT_TRUE(parse({"adig", "-v"}).version_requested);
    EXPECT_TRUE(parse({"adig", "--version"}).version_requested);
    EXPECT_FALSE(parse({"adig", "example.com"}).version_requested);
}

// --- +timeout= parsing ----------------------------------------------------

TEST(ParseTimeout, ValidValue) {
    ParseResult r = parse({"adig", "example.com", "+timeout=9"});
    ASSERT_TRUE(r.error.empty()) << r.error;
    EXPECT_EQ(Millis{9000}, r.opts.timeout);
}

TEST(ParseTimeout, BareOptionRequiresValue) {
    // A bare `+timeout` (no `=N`) must yield an actionable error instead of
    // the generic "invalid timeout: " fallback.
    ParseResult r = parse({"adig", "example.com", "+timeout"});
    EXPECT_FALSE(r.error.empty());
    EXPECT_NE(std::string::npos, r.error.find("requires a value"));
    EXPECT_NE(std::string::npos, r.error.find("+timeout=N"));
}

TEST(ParseTimeout, EmptyValueRequiresValue) {
    // `+timeout=` (empty value) must yield the same actionable error.
    ParseResult r = parse({"adig", "example.com", "+timeout="});
    EXPECT_FALSE(r.error.empty());
    EXPECT_NE(std::string::npos, r.error.find("requires a value"));
    EXPECT_NE(std::string::npos, r.error.find("+timeout=N"));
}

TEST(ParseTimeout, NonNumericValueRejected) {
    ParseResult r = parse({"adig", "example.com", "+timeout=abc"});
    EXPECT_FALSE(r.error.empty());
    EXPECT_NE(std::string::npos, r.error.find("invalid timeout"));
}

TEST(ParseTimeout, ZeroValueRejected) {
    ParseResult r = parse({"adig", "example.com", "+timeout=0"});
    EXPECT_FALSE(r.error.empty());
    EXPECT_NE(std::string::npos, r.error.find("invalid timeout"));
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

// --- bug #12: +trace sets the DNSSEC DO bit ----------------------------------

TEST(ParseTrace, SetsDnssecDoBit) {
    // dig's `+trace` sets `lookup->dnssec = true` (dig.c case 'a': trace)
    // so each iterative authoritative query requests DNSSEC records. Verified
    // against `dig +trace +qr` (the OPT PSEUDOSECTION in the first hop shows
    // `flags: do; udp: ...`). A later `+nodnssec` still wins (mirrors dig).
    ParseResult r = parse({"adig", "example.com", "+trace"});
    ASSERT_TRUE(r.error.empty()) << r.error;
    EXPECT_TRUE(r.opts.trace);
    EXPECT_TRUE(r.opts.dnssec);
}

TEST(ParseTrace, LaterNoDnssecOverridesTraceDnssec) {
    // `+trace +nodnssec`: like `+trace +stats`, the explicit later flag wins
    // over the trace-applied default (dig's order-sensitive precedence).
    ParseResult r = parse({"adig", "example.com", "+trace", "+nodnssec"});
    ASSERT_TRUE(r.error.empty()) << r.error;
    EXPECT_TRUE(r.opts.trace);
    EXPECT_FALSE(r.opts.dnssec);
}

TEST(ParseTrace, EarlierDnssecOverriddenByTrace) {
    // `+dnssec +trace`: +dnssec sets dnssec=true first, then +trace sets it
    // again to true (idempotent); the trailing trace-applied default is
    // `dnssec=true`, so the final value is true either way.
    ParseResult r = parse({"adig", "example.com", "+dnssec", "+trace"});
    ASSERT_TRUE(r.error.empty()) << r.error;
    EXPECT_TRUE(r.opts.trace);
    EXPECT_TRUE(r.opts.dnssec);
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
    // +all wins: every section-level flag ends up on (re-enabling the trace
    // defaults comments/question/stats). The field-level flags (multiline /
    // ttlid / cls) are NOT part of `+all`: multiline keeps its default (off),
    // and ttlid/cls keep their defaults (on) — matching `dig +trace +all`.
    const DisplayFlags &d = r.opts.display;
    EXPECT_TRUE(d.comments);
    EXPECT_TRUE(d.question);
    EXPECT_TRUE(d.stats);
    EXPECT_TRUE(d.answer);
    EXPECT_TRUE(d.authority);
    EXPECT_TRUE(d.additional);
    EXPECT_FALSE(d.multiline);
    EXPECT_TRUE(d.ttlid);
    EXPECT_TRUE(d.cls);
}

// --- apply_force_tcp (+tcp scheme rewrite) ---------------------------------

TEST(ApplyForceTcp, BareHostIsPrefixedWithTcp) {
    std::string server = "1.1.1.1";
    apply_force_tcp(server);
    EXPECT_EQ("tcp://1.1.1.1", server);
}

TEST(ApplyForceTcp, BareHostnameIsPrefixedWithTcp) {
    std::string server = "dns.adguard.com";
    apply_force_tcp(server);
    EXPECT_EQ("tcp://dns.adguard.com", server);
}

TEST(ApplyForceTcp, UdpSchemeBecomesTcp) {
    // Regression: replacing 4 chars dropped the colon, yielding "tcp//...".
    std::string server = "udp://1.1.1.1";
    apply_force_tcp(server);
    EXPECT_EQ("tcp://1.1.1.1", server);
}

TEST(ApplyForceTcp, UdpSchemeWithHostBecomesTcp) {
    std::string server = "udp://dns.adguard.com";
    apply_force_tcp(server);
    EXPECT_EQ("tcp://dns.adguard.com", server);
}

TEST(ApplyForceTcp, DnsSchemeBecomesTcp) {
    std::string server = "dns://1.1.1.1";
    apply_force_tcp(server);
    EXPECT_EQ("tcp://1.1.1.1", server);
}

TEST(ApplyForceTcp, SchemeMatchingIsCaseInsensitive) {
    // `+tcp` must take effect for uppercase/mixed-case scheme inputs too — the
    // plain-DNS scheme is otherwise treated case-insensitively elsewhere
    // (format_dig_server), so a `UDP://` / `Dns://` rewrite must keep parity.
    std::string udp_upper = "UDP://1.1.1.1";
    apply_force_tcp(udp_upper);
    EXPECT_EQ("tcp://1.1.1.1", udp_upper);

    std::string dns_mixed = "Dns://dns.adguard.com";
    apply_force_tcp(dns_mixed);
    EXPECT_EQ("tcp://dns.adguard.com", dns_mixed);

    std::string udp_mixed = "UdP://1.1.1.1:5353";
    apply_force_tcp(udp_mixed);
    EXPECT_EQ("tcp://1.1.1.1:5353", udp_mixed);
}

TEST(ApplyForceTcp, BareUdpLiteralIsPrefixedNotMangled) {
    // "udp" has no "://" separator, so it is treated as a bare host: the whole
    // string is prefixed (dig's `@udp` is a hostname, not a scheme).
    std::string server = "udp";
    apply_force_tcp(server);
    EXPECT_EQ("tcp://udp", server);
}

TEST(ApplyForceTcp, AlreadyTcpUnchanged) {
    std::string server = "tcp://1.1.1.1";
    apply_force_tcp(server);
    EXPECT_EQ("tcp://1.1.1.1", server);
}

TEST(ApplyForceTcp, EncryptedSchemesLeftUntouched) {
    for (std::string s : {
                 "tls://dns.adguard.com",
                 "https://dns.adguard.com/dns-query",
                 "quic://dns.adguard.com",
                 "sdns://AQMAAAAAAAAAFDE3Ni4xMDMuMTMwLjEzMDo1NDQz",
                 "system://",
         }) {
        std::string server = s;
        apply_force_tcp(server);
        EXPECT_EQ(s, server) << "encrypted scheme should be left untouched";
    }
}

TEST(ApplyForceTcp, EmptyStringGetsSchemePrefix) {
    std::string server;
    apply_force_tcp(server);
    EXPECT_EQ("tcp://", server);
}

// --- dig-compat no-op flags (accepted, no behavior change) ------------------

TEST(ParseNoopFlags, AcceptedWithoutError) {
    for (const char *opt : {"+aaflag", "+defname", "+showsearch", "+noaaflag", "+nodefname", "+noshowsearch"}) {
        ParseResult r = parse({"adig", "example.com", opt});
        EXPECT_TRUE(r.error.empty()) << opt << ": " << r.error;
    }
}

TEST(ParseNoopFlags, CombinationsDoNotError) {
    ParseResult r = parse({"adig", "example.com", "+showsearch", "+defname", "+aaflag", "+short"});
    ASSERT_TRUE(r.error.empty()) << r.error;
    EXPECT_TRUE(r.opts.short_output);
}

// --- +adflag / +cookie (functional CLI flags) ------------------------------

TEST(ParseAdFlag, DefaultsOn) {
    ParseResult r = parse({"adig", "example.com"});
    ASSERT_TRUE(r.error.empty());
    EXPECT_TRUE(r.opts.ad); // AD flag on by default (mirrors dig)
}

TEST(ParseAdFlag, NoAdFlagClears) {
    ParseResult r = parse({"adig", "example.com", "+noadflag"});
    ASSERT_TRUE(r.error.empty());
    EXPECT_FALSE(r.opts.ad);
}

TEST(ParseAdFlag, AdFlagSets) {
    ParseResult r = parse({"adig", "example.com", "+adflag"});
    ASSERT_TRUE(r.error.empty());
    EXPECT_TRUE(r.opts.ad); // +adflag is a no-op (default on) but accepted
}

TEST(ParseCookie, DefaultsOn) {
    ParseResult r = parse({"adig", "example.com"});
    ASSERT_TRUE(r.error.empty());
    EXPECT_TRUE(r.opts.cookie); // COOKIE on by default (mirrors dig)
}

TEST(ParseCookie, NoCookieClears) {
    ParseResult r = parse({"adig", "example.com", "+nocookie"});
    ASSERT_TRUE(r.error.empty());
    EXPECT_FALSE(r.opts.cookie);
}

TEST(ParseCookie, CookieSets) {
    ParseResult r = parse({"adig", "example.com", "+cookie"});
    ASSERT_TRUE(r.error.empty());
    EXPECT_TRUE(r.opts.cookie); // +cookie is a no-op (default on) but accepted
}

// --- +header-only (query construction flag) --------------------------------

TEST(ParseHeaderOnly, SetsFlag) {
    ParseResult r = parse({"adig", "example.com", "+header-only"});
    ASSERT_TRUE(r.error.empty());
    EXPECT_TRUE(r.opts.header_only);
}

TEST(ParseHeaderOnly, DefaultsOff) {
    ParseResult r = parse({"adig", "example.com"});
    ASSERT_TRUE(r.error.empty());
    EXPECT_FALSE(r.opts.header_only);
}

// --- -p PORT ----------------------------------------------------------------

TEST(ParsePort, ValidValue) {
    EXPECT_EQ(5353u, parse({"adig", "example.com", "-p", "5353"}).opts.port.value_or(0));
    EXPECT_EQ(53u, parse({"adig", "example.com", "-p", "53"}).opts.port.value_or(0));
}

TEST(ParsePort, MissingArgIsError) {
    ParseResult r = parse({"adig", "example.com", "-p"});
    EXPECT_FALSE(r.error.empty());
    EXPECT_NE(std::string::npos, r.error.find("port"));
}

TEST(ParsePort, InvalidValueRejected) {
    EXPECT_FALSE(parse({"adig", "example.com", "-p", "0"}).error.empty());
    EXPECT_FALSE(parse({"adig", "example.com", "-p", "65536"}).error.empty());
    EXPECT_FALSE(parse({"adig", "example.com", "-p", "abc"}).error.empty());
}

TEST(ApplyPort, AppendsToBareHost) {
    std::string s = "1.1.1.1";
    apply_port(s, 5353);
    EXPECT_EQ("1.1.1.1:5353", s);
}

TEST(ApplyPort, OverridesExplicitPort) {
    std::string s = "1.1.1.1:53";
    apply_port(s, 5353);
    EXPECT_EQ("1.1.1.1:5353", s);
}

TEST(ApplyPort, UnsetLeavesServer) {
    std::string s = "1.1.1.1";
    apply_port(s, std::nullopt);
    EXPECT_EQ("1.1.1.1", s);
}

TEST(ApplyPort, SchemedServerLeftUntouched) {
    std::string s = "tls://dns.adguard.com";
    apply_port(s, 5353);
    EXPECT_EQ("tls://dns.adguard.com", s);
}

TEST(ApplyPort, HostnameWithoutDot) {
    std::string s = "localhost";
    apply_port(s, 5353);
    EXPECT_EQ("localhost:5353", s);
}

TEST(ApplyPort, HostnameWithoutDotButExplicitPort) {
    // Regression: a dot-less hostname with its own `:port` was previously left
    // unsplit (the old dot-guard skipped it), producing an invalid
    // `localhost:53:5353`. The single-colon split now strips the explicit port.
    std::string s = "localhost:53";
    apply_port(s, 5353);
    EXPECT_EQ("localhost:5353", s);
}

TEST(ApplyPort, BareIpv6LiteralLeftAlone) {
    // A bare IPv6 literal carries two or more colons and must not be mis-split
    // on one of its own colons; the port is appended (mirroring the prior
    // behavior, since parsing a bare IPv6 + port is not otherwise supported).
    std::string s = "::1";
    apply_port(s, 5353);
    EXPECT_EQ("::1:5353", s);
}

// --- +bufsize / +ednsflags / +opcode (parsing) -----------------------------
//
// The apply_dns_flags behavior for these (DO bit, EDNS Z field, opcode applied
// last) is covered in test_adig_cli_packet.cpp; here only the parse_args
// plumbing is exercised.

TEST(ParseBufsize, ValuePropagates) {
    EXPECT_EQ(512u, parse({"adig", "example.com", "+bufsize=512"}).opts.edns_bufsize);
    EXPECT_EQ(1232u, parse({"adig", "example.com", "+bufsize=1232"}).opts.edns_bufsize);
    EXPECT_EQ(0u, parse({"adig", "example.com"}).opts.edns_bufsize); // unset -> default 4096
}

TEST(ParseBufsize, InvalidRejected) {
    EXPECT_FALSE(parse({"adig", "example.com", "+bufsize"}).error.empty());
    EXPECT_FALSE(parse({"adig", "example.com", "+bufsize=0"}).error.empty());
    EXPECT_FALSE(parse({"adig", "example.com", "+bufsize=70000"}).error.empty());
    EXPECT_FALSE(parse({"adig", "example.com", "+nobufsize=512"}).error.empty());
}

TEST(ParseEdnsFlags, ValueParsed) {
    EXPECT_EQ(0x80u, parse({"adig", "example.com", "+ednsflags=0x80"}).opts.edns_flags.value_or(0));
    EXPECT_EQ(0x80u, parse({"adig", "example.com", "+ednsflags=128"}).opts.edns_flags.value_or(0));
    EXPECT_EQ(0xFFFFu, parse({"adig", "example.com", "+ednsflags=0xffff"}).opts.edns_flags.value_or(0));
    EXPECT_FALSE(parse({"adig", "example.com", "+noednsflags"}).opts.edns_flags.has_value());
}

TEST(ParseEdnsFlags, InvalidRejected) {
    EXPECT_FALSE(parse({"adig", "example.com", "+ednsflags"}).error.empty());
    EXPECT_FALSE(parse({"adig", "example.com", "+ednsflags=0xZZ"}).error.empty());
    EXPECT_FALSE(parse({"adig", "example.com", "+ednsflags=65536"}).error.empty());
}

TEST(ParseOpcode, NamesAndNumeric) {
    EXPECT_EQ(LDNS_PACKET_NOTIFY, parse_opcode_name("NOTIFY").value_or(LDNS_PACKET_QUERY));
    EXPECT_EQ(LDNS_PACKET_UPDATE, parse_opcode_name("update").value_or(LDNS_PACKET_QUERY));
    EXPECT_EQ(LDNS_PACKET_QUERY, parse_opcode_name("QUERY").value_or(LDNS_PACKET_NOTIFY));
    EXPECT_EQ(LDNS_PACKET_STATUS, parse_opcode_name("status").value_or(LDNS_PACKET_QUERY));
    EXPECT_EQ(LDNS_PACKET_NOTIFY, parse_opcode_name("4").value_or(LDNS_PACKET_QUERY)); // numeric
    EXPECT_EQ(LDNS_PACKET_UPDATE, parse_opcode_name("5").value_or(LDNS_PACKET_QUERY));
    EXPECT_FALSE(parse_opcode_name("BOGUS").has_value());
    EXPECT_FALSE(parse_opcode_name("16").has_value()); // out of range
    EXPECT_FALSE(parse_opcode_name("").has_value());
}

TEST(ParseOpcode, ValuePropagates) {
    EXPECT_EQ(LDNS_PACKET_NOTIFY,
            parse({"adig", "example.com", "+opcode=NOTIFY"}).opts.opcode.value_or(LDNS_PACKET_QUERY));
    EXPECT_FALSE(parse({"adig", "example.com", "+noopcode"}).opts.opcode.has_value());
    EXPECT_FALSE(parse({"adig", "example.com", "+opcode=BOGUS"}).error.empty());
    EXPECT_FALSE(parse({"adig", "example.com", "+opcode"}).error.empty());
}

// --- +ednsopt (generic EDNS option, RFC 6891) ------------------------------
//
// `dig +ednsopt=CODE[:hexvalue]`: CODE is a case-insensitive mnemonic
// (mirroring dig's `optnames`) or a decimal number (0..65535); the optional
// `:hexvalue` is the option-data payload decoded as hex (whitespace ignored,
// odd-length / non-hex rejected). Repeatable; `+noednsopt` clears the list.

TEST(ParseEdnsopt, MnemonicAndNumericCode) {
    ParseResult r = parse({"adig", "example.com", "+ednsopt=nsid"});
    ASSERT_TRUE(r.error.empty()) << r.error;
    ASSERT_EQ(1u, r.opts.ednsopts.size());
    EXPECT_EQ(3u, r.opts.ednsopts[0].code);
    EXPECT_TRUE(r.opts.ednsopts[0].data.empty());
    // Decimal numeric code is equivalent to its mnemonic.
    EXPECT_EQ(3u, parse({"adig", "example.com", "+ednsopt=3"}).opts.ednsopts[0].code);
}

TEST(ParseEdnsopt, HexPayloadDecoded) {
    ParseResult r = parse({"adig", "example.com", "+ednsopt=3:414243"});
    ASSERT_TRUE(r.error.empty()) << r.error;
    ASSERT_EQ(1u, r.opts.ednsopts.size());
    EXPECT_EQ(3u, r.opts.ednsopts[0].code);
    EXPECT_EQ((Bytes{0x41, 0x42, 0x43}), r.opts.ednsopts[0].data);
}

TEST(ParseEdnsopt, MnemonicCaseInsensitiveWithPayload) {
    ParseResult r = parse({"adig", "example.com", "+ednsopt=NSID:abcd"});
    ASSERT_TRUE(r.error.empty()) << r.error;
    ASSERT_EQ(1u, r.opts.ednsopts.size());
    EXPECT_EQ(3u, r.opts.ednsopts[0].code);
    EXPECT_EQ((Bytes{0xab, 0xcd}), r.opts.ednsopts[0].data);
}

TEST(ParseEdnsopt, WhitespaceInPayload) {
    // Mirrors ISC's hex decoder, which skips ASCII whitespace.
    ParseResult r = parse({"adig", "example.com", "+ednsopt=3:41 42"});
    ASSERT_TRUE(r.error.empty()) << r.error;
    EXPECT_EQ((Bytes{0x41, 0x42}), r.opts.ednsopts[0].data);
}

TEST(ParseEdnsopt, Repeatable) {
    ParseResult r = parse({"adig", "example.com", "+ednsopt=3", "+ednsopt=12:0000"});
    ASSERT_TRUE(r.error.empty()) << r.error;
    ASSERT_EQ(2u, r.opts.ednsopts.size());
    EXPECT_EQ(3u, r.opts.ednsopts[0].code);
    EXPECT_TRUE(r.opts.ednsopts[0].data.empty());
    EXPECT_EQ(12u, r.opts.ednsopts[1].code);
    EXPECT_EQ((Bytes{0x00, 0x00}), r.opts.ednsopts[1].data);
}

TEST(ParseEdnsopt, NoEdnsoptClearsList) {
    // `+noednsopt` clears the previously-added options (dig ignores any value).
    ParseResult r = parse({"adig", "example.com", "+ednsopt=3", "+ednsopt=12", "+noednsopt"});
    ASSERT_TRUE(r.error.empty()) << r.error;
    EXPECT_TRUE(r.opts.ednsopts.empty());
    // A later `+ednsopt` after `+noednsopt` adds fresh.
    r = parse({"adig", "example.com", "+noednsopt", "+ednsopt=3"});
    ASSERT_TRUE(r.error.empty()) << r.error;
    ASSERT_EQ(1u, r.opts.ednsopts.size());
    EXPECT_EQ(3u, r.opts.ednsopts[0].code);
}

TEST(ParseEdnsopt, NoEdnsoptIgnoresValue) {
    // `+noednsopt=anything` clears and is accepted (dig likewise ignores the value).
    ParseResult r = parse({"adig", "example.com", "+ednsopt=3", "+noednsopt=99"});
    ASSERT_TRUE(r.error.empty()) << r.error;
    EXPECT_TRUE(r.opts.ednsopts.empty());
}

TEST(ParseEdnsopt, BareOptionRequiresCode) {
    // A bare `+ednsopt` (no `=CODE`) is an error, mirroring dig's
    // "ednsopt no code point specified".
    ParseResult r = parse({"adig", "example.com", "+ednsopt"});
    EXPECT_FALSE(r.error.empty());
    EXPECT_NE(std::string::npos, r.error.find("requires a code"));
    // `+ednsopt=` (empty code) likewise.
    EXPECT_FALSE(parse({"adig", "example.com", "+ednsopt="}).error.empty());
}

TEST(ParseEdnsopt, InvalidCodeRejected) {
    EXPECT_FALSE(parse({"adig", "example.com", "+ednsopt=bogus"}).error.empty());
    EXPECT_FALSE(parse({"adig", "example.com", "+ednsopt=65536"}).error.empty()); // out of range
    // Empty code before a payload (`+ednsopt=:4142`) is invalid.
    EXPECT_FALSE(parse({"adig", "example.com", "+ednsopt=:4142"}).error.empty());
}

TEST(ParseEdnsopt, InvalidPayloadRejected) {
    // Non-hex or odd-length payloads are rejected.
    EXPECT_FALSE(parse({"adig", "example.com", "+ednsopt=3:gg"}).error.empty());
    EXPECT_FALSE(parse({"adig", "example.com", "+ednsopt=3:414"}).error.empty());
}

} // namespace ag::adig::test
