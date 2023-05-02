#include <gtest/gtest.h>
#include <numeric>
#include <string>

#include "common/file.h"
#include "common/logger.h"
#include "common/utils.h"
#include "dns/common/sys.h"
#include "dns/dnsfilter/dnsfilter.h"

#include "../rule_utils.h"

namespace ag::dns::dnsfilter::test {

class DnsfilterTest : public ::testing::Test {
protected:
    DnsFilter filter;
    ag::file::Handle file;
    Logger log{"dnsfilter_test"};

    const std::string TEST_FILTER_NAME = "dnsfilter_test";

    void SetUp() override {
        Logger::set_log_level(LogLevel::LOG_LEVEL_TRACE);
        file = ag::file::open(file_by_filter_name(TEST_FILTER_NAME), ag::file::CREAT | ag::file::RDONLY);
        ASSERT_TRUE(ag::file::is_valid(file)) << ag::dns::sys::error_string(ag::dns::sys::error_code());
        ag::file::close(file);
    }

    void TearDown() override {
        std::remove(file_by_filter_name(TEST_FILTER_NAME).data());
    }

    static void clear_filter(std::string_view filter) {
        ag::file::Handle file = ag::file::open(std::string(filter), ag::file::WRONLY | ag::file::TRUNC);
        ASSERT_TRUE(ag::file::is_valid(file)) << ag::dns::sys::error_string(ag::dns::sys::error_code());
        ASSERT_EQ(0, ag::file::get_size(file)) << ag::dns::sys::error_string(ag::dns::sys::error_code());
        ag::file::close(file);
    }

    static void add_rule_in_filter(std::string_view filter, std::string_view rule) {
        ag::file::Handle file = ag::file::open(std::string(filter), ag::file::WRONLY);
        ASSERT_TRUE(ag::file::is_valid(file)) << ag::dns::sys::error_string(ag::dns::sys::error_code());
        ASSERT_GE(ag::file::get_size(file), 0) << ag::dns::sys::error_string(ag::dns::sys::error_code());
        ASSERT_EQ(ag::file::get_size(file), ag::file::set_position(file, ag::file::get_size(file)));
        EXPECT_EQ(ag::file::write(file, rule.data(), rule.length()), rule.length());
        EXPECT_EQ(ag::file::write(file, "\n", 1), 1);
        ag::file::close(file);
    }

    static std::string file_by_filter_name(std::string filter) {
        return filter + ".txt";
    }
};

TEST_F(DnsfilterTest, SuccessfulRuleParsing) {
    struct TestData {
        std::string text;
        rule_utils::Rule expected_rule;
    };

    static constexpr auto make_rule = [](DnsFilter::AdblockRuleInfo::PropsSet p = 0) -> DnsFilter::Rule {
        DnsFilter::Rule r = {.content = DnsFilter::AdblockRuleInfo{p}};
        return r;
    };

    const TestData TEST_DATA[] = {
            {"||*.example.*", {make_rule(), rule_utils::Rule::MMID_SHORTCUTS_AND_REGEX}},
            {"||*example*", {make_rule(), rule_utils::Rule::MMID_SHORTCUTS_AND_REGEX}},
            {"example.org", {make_rule(), rule_utils::Rule::MMID_EXACT}},
            {"exampleorg", {make_rule(), rule_utils::Rule::MMID_EXACT}},
            {"example-org", {make_rule(), rule_utils::Rule::MMID_EXACT}},
            {"example_org", {make_rule(), rule_utils::Rule::MMID_EXACT}},
            {"_exampleorg", {make_rule(), rule_utils::Rule::MMID_EXACT}},
            {"ttp", {make_rule(), rule_utils::Rule::MMID_EXACT}},
            {"ab", {make_rule(), rule_utils::Rule::MMID_EXACT}}, // It is NOT too wide
            {"@@example.org", {make_rule(1 << DnsFilter::DARP_EXCEPTION), rule_utils::Rule::MMID_SHORTCUTS}},
            {"example.org$important", {make_rule(1 << DnsFilter::DARP_IMPORTANT), rule_utils::Rule::MMID_SHORTCUTS}},
            {"@@example.org$important",
                    {make_rule((1 << DnsFilter::DARP_EXCEPTION) | (1 << DnsFilter::DARP_IMPORTANT)),
                            rule_utils::Rule::MMID_SHORTCUTS}},
            {"|example.org", {make_rule(), rule_utils::Rule::MMID_SHORTCUTS_AND_REGEX}},
            {"example.org|", {make_rule(), rule_utils::Rule::MMID_SHORTCUTS_AND_REGEX}},
            {"|example.org|", {make_rule(), rule_utils::Rule::MMID_EXACT}},
            {".example", {make_rule(), rule_utils::Rule::MMID_SHORTCUTS}},
            {"example.", {make_rule(), rule_utils::Rule::MMID_SHORTCUTS}},
            {"*example.org", {make_rule(), rule_utils::Rule::MMID_SHORTCUTS}},
            {"||example.org|", {make_rule(), rule_utils::Rule::MMID_SUBDOMAINS}},
            {"||example.org^", {make_rule(), rule_utils::Rule::MMID_SUBDOMAINS}},
            {"||example.org", {make_rule(), rule_utils::Rule::MMID_SHORTCUTS_AND_REGEX}},
            {"/example.org/", {make_rule(), rule_utils::Rule::MMID_SHORTCUTS_AND_REGEX}},
            {"/example.org/$badfilter", {make_rule(1 << DnsFilter::DARP_BADFILTER)}},
            {"/ex[a]?mple.org/", {make_rule(), rule_utils::Rule::MMID_REGEX}},
            {"/ex[ab]mple.org/", {make_rule(), rule_utils::Rule::MMID_SHORTCUTS_AND_REGEX}},
            {"example.org$badfilter", {make_rule(1 << DnsFilter::DARP_BADFILTER)}},
            {"-ad-banner.", {make_rule(), rule_utils::Rule::MMID_SHORTCUTS}},
            {"-ad-unit/", {make_rule(), rule_utils::Rule::MMID_SHORTCUTS_AND_REGEX}},
            {"-ad-unit^", {make_rule(), rule_utils::Rule::MMID_SHORTCUTS_AND_REGEX}},
            {"-ad-unit/^", {make_rule(), rule_utils::Rule::MMID_SHORTCUTS_AND_REGEX}},
            {"-ad-unit^/", {make_rule(), rule_utils::Rule::MMID_SHORTCUTS_AND_REGEX}},
            {"||adminpromotion.com^", {make_rule(), rule_utils::Rule::MMID_SUBDOMAINS}},
            {"||travelstool.com^", {make_rule(), rule_utils::Rule::MMID_SUBDOMAINS}},
            {"example.org:8080", {make_rule(), rule_utils::Rule::MMID_SHORTCUTS_AND_REGEX}},
            {"//example.org:8080", {make_rule(), rule_utils::Rule::MMID_SUBDOMAINS}},
            {"://example.org", {make_rule(), rule_utils::Rule::MMID_SHORTCUTS_AND_REGEX}},
            {"://example.org/", {make_rule(), rule_utils::Rule::MMID_SUBDOMAINS}},
            {"http://example.org/", {make_rule(), rule_utils::Rule::MMID_SUBDOMAINS}},
            {"https://example.org|", {make_rule(), rule_utils::Rule::MMID_SUBDOMAINS}},
            {"ws://example.org|", {make_rule(), rule_utils::Rule::MMID_SUBDOMAINS}},
            {"example.org^|", {make_rule(), rule_utils::Rule::MMID_SHORTCUTS_AND_REGEX}},
            {"example.org|^", {make_rule(), rule_utils::Rule::MMID_SHORTCUTS_AND_REGEX}},
            {"|example.org^", {make_rule(), rule_utils::Rule::MMID_EXACT}},
            {"|https://example31.org/", {make_rule(), rule_utils::Rule::MMID_EXACT}},
            {"/127.0.0.1/", {make_rule(), rule_utils::Rule::MMID_SHORTCUTS_AND_REGEX}},
            {"/12:34:56:78::90/", {make_rule(), rule_utils::Rule::MMID_SHORTCUTS_AND_REGEX}},
            {"123.123.123.123", {make_rule(), rule_utils::Rule::MMID_SHORTCUTS}},
            {"12:34:56:78::90", {make_rule(), rule_utils::Rule::MMID_SHORTCUTS}},
            {"123.123.123.123$badfilter", {make_rule(1 << DnsFilter::DARP_BADFILTER), rule_utils::Rule::MMID_EXACT}},
            {"12:34:56:78::90$badfilter", {make_rule(1 << DnsFilter::DARP_BADFILTER), rule_utils::Rule::MMID_EXACT}},
            {"@@123.123.123.123", {make_rule(1 << DnsFilter::DARP_EXCEPTION), rule_utils::Rule::MMID_SHORTCUTS}},
            {"@@12:34:56:78::90", {make_rule(1 << DnsFilter::DARP_EXCEPTION), rule_utils::Rule::MMID_SHORTCUTS}},
            {"0.0.0.0", {make_rule(), rule_utils::Rule::MMID_SHORTCUTS}},
            {"::1", {make_rule(), rule_utils::Rule::MMID_SHORTCUTS}},
            {"|123.123.123.123^", {make_rule(), rule_utils::Rule::MMID_EXACT}},
            {"|12:34:56:78::90^", {make_rule(), rule_utils::Rule::MMID_EXACT}},
            {"||123.123.123.123^", {make_rule(), rule_utils::Rule::MMID_SUBDOMAINS}},
            {"||12:34:56:78::90^", {make_rule(), rule_utils::Rule::MMID_SUBDOMAINS}},
            {"http://123.123.123.123", {make_rule(), rule_utils::Rule::MMID_SHORTCUTS_AND_REGEX}},
            {"http://12:34:56:78::90^", {make_rule(), rule_utils::Rule::MMID_SUBDOMAINS}},
            {"https://123.123.123.123", {make_rule(), rule_utils::Rule::MMID_SHORTCUTS_AND_REGEX}},
            {"https://12:34:56:78::90^", {make_rule(), rule_utils::Rule::MMID_SUBDOMAINS}},
            {"172.16.*.1", {make_rule(), rule_utils::Rule::MMID_SHORTCUTS}},
            {"172.16.*.1:80", {make_rule(), rule_utils::Rule::MMID_SHORTCUTS_AND_REGEX}},
            {"|172.16.*.1:80^", {make_rule(), rule_utils::Rule::MMID_SHORTCUTS_AND_REGEX}},
            {"1.1.1.0/24", {make_rule(), rule_utils::Rule::MMID_CIDR}},
            {"@@1.1.1.0/24", {make_rule(1 << DnsFilter::DARP_EXCEPTION), rule_utils::Rule::MMID_CIDR}},
            {"example.org$dnstype=A", {make_rule(1 << DnsFilter::DARP_DNSTYPE), rule_utils::Rule::MMID_SHORTCUTS}},
            {"example.org$dnstype=AAAA", {make_rule(1 << DnsFilter::DARP_DNSTYPE), rule_utils::Rule::MMID_SHORTCUTS}},
            {"example.org$dnstype=~A", {make_rule(1 << DnsFilter::DARP_DNSTYPE), rule_utils::Rule::MMID_SHORTCUTS}},
            {"example.org$dnstype=A|AAAA", {make_rule(1 << DnsFilter::DARP_DNSTYPE), rule_utils::Rule::MMID_SHORTCUTS}},
            {"example.org$dnstype=A|~AAAA",
                    {make_rule(1 << DnsFilter::DARP_DNSTYPE), rule_utils::Rule::MMID_SHORTCUTS}},
            {"@@example.org$dnstype=A",
                    {make_rule((1 << DnsFilter::DARP_EXCEPTION) | (1 << DnsFilter::DARP_DNSTYPE)),
                            rule_utils::Rule::MMID_SHORTCUTS}},
            {"@@example.org$dnstype",
                    {make_rule((1 << DnsFilter::DARP_EXCEPTION) | (1 << DnsFilter::DARP_DNSTYPE)),
                            rule_utils::Rule::MMID_SHORTCUTS}},
            {"@@example.org$dnstype=a",
                    {make_rule((1 << DnsFilter::DARP_EXCEPTION) | (1 << DnsFilter::DARP_DNSTYPE)),
                            rule_utils::Rule::MMID_SHORTCUTS}},
            {"||4.3.2.1.in-addr.arpa.^$dnsrewrite=REFUSED;PTR;example.net.",
                    {make_rule((1 << DnsFilter::DARP_DNSREWRITE)), rule_utils::Rule::MMID_SUBDOMAINS}},
            {"example.org$dnsrewrite=NOERROR;A;1.2.3.4",
                    {make_rule((1 << DnsFilter::DARP_DNSREWRITE)), rule_utils::Rule::MMID_SHORTCUTS}},
            {"example.org$dnsrewrite=SERVFAIL;CNAME;example.org",
                    {make_rule((1 << DnsFilter::DARP_DNSREWRITE)), rule_utils::Rule::MMID_SHORTCUTS}},
            {"example.org$dnsrewrite=NOERROR;MX;42 example.mail",
                    {make_rule((1 << DnsFilter::DARP_DNSREWRITE)), rule_utils::Rule::MMID_SHORTCUTS}},
            {"example.org$dnsrewrite=FORMERR;TXT;hello_world",
                    {make_rule((1 << DnsFilter::DARP_DNSREWRITE)), rule_utils::Rule::MMID_SHORTCUTS}},
            {"example.org$dnsrewrite=NXDOMAIN;;",
                    {make_rule((1 << DnsFilter::DARP_DNSREWRITE)), rule_utils::Rule::MMID_SHORTCUTS}},
            {"example.org$dnsrewrite=NOERROR;SVCB;1 .",
                    {make_rule((1 << DnsFilter::DARP_DNSREWRITE)), rule_utils::Rule::MMID_SHORTCUTS}},
            {"example.org$dnsrewrite=NOERROR;HTTPS;1 example.net alpn=h3",
                    {make_rule((1 << DnsFilter::DARP_DNSREWRITE)), rule_utils::Rule::MMID_SHORTCUTS}},
            {"example.org$dnsrewrite",
                    {make_rule((1 << DnsFilter::DARP_DNSREWRITE)), rule_utils::Rule::MMID_SHORTCUTS}},
            {"@@example.org$dnsrewrite=1.2.3.4",
                    {make_rule((1 << DnsFilter::DARP_DNSREWRITE) | (1 << DnsFilter::DARP_EXCEPTION)),
                            rule_utils::Rule::MMID_SHORTCUTS}},
            {"@@example.org$dnsrewrite=abcd::1234",
                    {make_rule((1 << DnsFilter::DARP_DNSREWRITE) | (1 << DnsFilter::DARP_EXCEPTION)),
                            rule_utils::Rule::MMID_SHORTCUTS}},
            {"@@example.org$dnsrewrite=example.net",
                    {make_rule((1 << DnsFilter::DARP_DNSREWRITE) | (1 << DnsFilter::DARP_EXCEPTION)),
                            rule_utils::Rule::MMID_SHORTCUTS}},
            {"@@example.org$dnsrewrite=NOTIMPL",
                    {make_rule((1 << DnsFilter::DARP_DNSREWRITE) | (1 << DnsFilter::DARP_EXCEPTION)),
                            rule_utils::Rule::MMID_SHORTCUTS}},
            {"@@example.org$dnsrewrite",
                    {make_rule((1 << DnsFilter::DARP_DNSREWRITE) | (1 << DnsFilter::DARP_EXCEPTION)),
                            rule_utils::Rule::MMID_SHORTCUTS}},
            {"*$dnstype=HTTPS", {make_rule(1 << DnsFilter::DARP_DNSTYPE), rule_utils::Rule::MMID_SHORTCUTS_AND_REGEX}},
            {"$dnstype=HTTPS", {make_rule(1 << DnsFilter::DARP_DNSTYPE), rule_utils::Rule::MMID_SHORTCUTS_AND_REGEX}},
            {"/.*/$dnstype=HTTPS", {make_rule(1 << DnsFilter::DARP_DNSTYPE), rule_utils::Rule::MMID_REGEX}},
            {"/.*$/$dnstype=HTTPS", {make_rule(1 << DnsFilter::DARP_DNSTYPE), rule_utils::Rule::MMID_REGEX}},
            {"*$dnsrewrite", {make_rule((1 << DnsFilter::DARP_DNSREWRITE)), rule_utils::Rule::MMID_SHORTCUTS_AND_REGEX}},
            {"$dnsrewrite", {make_rule((1 << DnsFilter::DARP_DNSREWRITE)), rule_utils::Rule::MMID_SHORTCUTS_AND_REGEX}},
            {"/.*/$dnsrewrite", {make_rule((1 << DnsFilter::DARP_DNSREWRITE)), rule_utils::Rule::MMID_REGEX}},
    };

    for (const TestData &entry : TEST_DATA) {
        infolog(log, "testing {}", entry.text);
        std::optional<rule_utils::Rule> rule = rule_utils::parse(entry.text, &log);
        ASSERT_TRUE(rule.has_value());
        const auto *content = std::get_if<DnsFilter::AdblockRuleInfo>(&rule->public_part.content);
        ASSERT_NE(content, nullptr);
        ASSERT_EQ(content->props, std::get<DnsFilter::AdblockRuleInfo>(entry.expected_rule.public_part.content).props);
        ASSERT_EQ(rule->match_method, entry.expected_rule.match_method);
    }
}

TEST_F(DnsfilterTest, SuccessfulHostsRuleParsing) {
    struct TestData {
        std::string text;
        rule_utils::Rule expected_rule;
    };

    const TestData TEST_DATA[] = {
            {"0.0.0.0 example.org",
                    {{.content = DnsFilter::HostsRuleInfo{"0.0.0.0"}}, rule_utils::Rule::MMID_SUBDOMAINS}},
            {"1:1:: example.org", {{.content = DnsFilter::HostsRuleInfo{"1:1::"}}, rule_utils::Rule::MMID_SUBDOMAINS}},
            {"1:1:1:1:1:1:1:1 example.org",
                    {{.content = DnsFilter::HostsRuleInfo{"1:1:1:1:1:1:1:1"}}, rule_utils::Rule::MMID_SUBDOMAINS}},
            {"::1:1 example.org", {{.content = DnsFilter::HostsRuleInfo{"::1:1"}}, rule_utils::Rule::MMID_SUBDOMAINS}},
            {"::FFFF:1.1.1.1 example.org",
                    {{.content = DnsFilter::HostsRuleInfo{"::FFFF:1.1.1.1"}}, rule_utils::Rule::MMID_SUBDOMAINS}},
            {"0.0.0.0 example.org #comment",
                    {{.content = DnsFilter::HostsRuleInfo{"0.0.0.0"}}, rule_utils::Rule::MMID_SUBDOMAINS}},
    };

    for (const TestData &entry : TEST_DATA) {
        infolog(log, "testing {}", entry.text);
        std::optional<rule_utils::Rule> rule = rule_utils::parse(entry.text, &log);
        ASSERT_TRUE(rule.has_value());
        const auto *content = std::get_if<DnsFilter::HostsRuleInfo>(&rule->public_part.content);
        ASSERT_NE(content, nullptr);
        ASSERT_EQ(content->ip, std::get<DnsFilter::HostsRuleInfo>(entry.expected_rule.public_part.content).ip);
        ASSERT_EQ(rule->match_method, entry.expected_rule.match_method);
    }
}

TEST_F(DnsfilterTest, WrongRuleParsing) {
    const std::string TEST_DATA[] = {
            "",
            "!example.com",
            "#example.com",
            "@example",
            "||||example",
            "||example$unknown",
            "||example$important,important",
            "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee.example.org",
            "eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee."
            "eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee."
            "eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee."
            "eeee.org",
            "?example.org",
            "^",
            "*",
            "/[example.org/",
            "&admeld_",
            "+advertorial.",
            "?ad_partner=",
            "@@||flashx.tv/js/xfs.js",
            "example.com/page",
            "example.com^some",
            "example.com|some",
            "example.com/^page",
            "|||example.com",
            "example.com^|^",
            "example.com//",
            "/example.com",
            "///example.com",
            "333.333.333.333 example.org",
            "45:67 example.org",
            "example.org$dnstype",
            "example.org$dnstypee",
            "example.org$dnstype=",
            "example.org$dnstype=~",
            "example.org$dnstype=OOPS",
            "example.org$dnstype=A|A",
            "example.org$dnstype=A|~A",
            "||example.org^$dnsrewrite=bad;syntax",
            "||example.org^$dnsrewrite=nonexisting;nonexisting;nonexisting",
            "||example.org^$dnsrewrite=NOERROR;nonexisting;nonexisting",
            "||example.org^$dnsrewrite=NOERROR;A;badip",
            "||example.org^$dnsrewrite=NOERROR;AAAA;badip",
            "||example.org^$dnsrewrite=NOERROR;AAAA;127.0.0.1",
            "||example.org^$dnsrewrite=NOERROR;;127.0.0.1",
            "||example.org^$dnsrewrite=REFUSED;PTR;example.net.",
            "||4.3.2.1.in-addr.arpa.^$dnsrewrite=REFUSED;PTR;example.net",
            "||4.3.2.1.in-addr.arpa^$dnsrewrite=REFUSED;PTR;example.net.",
            "4.3.2.1.in-addr.arpa.^$dnsrewrite=REFUSED;PTR;example.net.",
            "||4.3.2.1.in-addr.arpa.$dnsrewrite=REFUSED;PTR;example.net.",
            "4.3.2.1.in-addr.arpa.$dnsrewrite=REFUSED;PTR;example.net.",
            "example.org$dnsrewrite=NOERROR;MX;65536 example.mail",
            "example.org$dnsrewrite=NOERROR;MX;-42 example.mail",
            "example.org$dnsrewrite=NOERROR;MX;42 ***xxx@@@1!!",
            "example.org$dnsrewrite=NOERROR;MX;xx example.mail",
            "example.org$dnsrewrite=NOERROR;HTTPS;65536 example.net alpn=h3",
            "example.org$dnsrewrite=NOERROR;HTTPS;1 xxx@@@111 alpn=h3",
            "example.org$dnsrewrite=NOERROR;SVCB;1 . nonexisting=foo",
            "example.org$dnsrewrite=NOERROR;SVCB;example.org nonexisting=foo",
            "::",
            "*a",
            "a*",
            ".*",
            "example.org$denyallow",
            "example.org$denyallow=",
    };

    for (const std::string &entry : TEST_DATA) {
        infolog(log, "testing {}", entry);
        std::optional<rule_utils::Rule> rule = rule_utils::parse(entry, &log);
        ASSERT_FALSE(rule.has_value());
    }
}

struct BasicTestData {
    std::vector<std::string> rules;
    std::string domain;
    bool expect_blocked;
};

const std::vector<BasicTestData> BASIC_TEST_DATA = {
        {
                {"||*example-1*"},
                "sub.baexample-1ab",
                true,
        },
        {
                {"||*.example0.*"},
                "sub.example0.com",
                true,
        },
        {
                {"example1.org"},
                "example1.org",
                true,
        },
        {
                {"example2.org", "@@example2.org"},
                "example2.org",
                false,
        },
        {
                {"example3.org", "@@example3.org", "example3.org$important"},
                "example3.org",
                true,
        },
        {
                {"example4.org", "@@example4.org", "example4.org$important", "@@example4.org$important"},
                "example4.org",
                false,
        },
        {
                {"example5.org^"},
                "example5.org",
                true,
        },
        {
                {"||example6.org|"},
                "example6.org",
                true,
        },
        {
                {"*mple7.org"},
                "example7.org",
                true,
        },
        {
                {"ExAmPlE8.org"},
                "example8.org",
                true,
        },
        {
                {"example9.org"},
                "EXAMPLE9.org",
                true,
        },
        {
                {".example10.org"},
                "sub.example10.org",
                true,
        },
        {
                {"http://example11.org"},
                "example11.org",
                true,
        },
        {
                {"http://example111.org"},
                "example111.org1",
                true,
        },
        {
                {"http://example1111.org"},
                "sub.example1111.org1",
                true,
        },
        {
                {"://example12.org"},
                "example12.org",
                true,
        },
        {
                {"//example13.org"},
                "sub.example13.org",
                true,
        },
        {
                {"example15.org/"},
                "example15.org",
                true,
        },
        {
                {"example16.org/"},
                "eexample16.org",
                true,
        },
        {
                {"example17.org:8080"},
                "example17.org",
                true,
        },
        {
                {"example18.org|"},
                "eexample18.org",
                true,
        },
        {
                {"example19.org^"},
                "eexample19.org",
                true,
        },
        {
                {"|example20.org"},
                "example20.orgg",
                true,
        },
        {
                {"example21."},
                "eexample21.org",
                true,
        },
        {
                {"example22.org|"},
                "sub.example22.org",
                true,
        },
        {
                {"example23.org^"},
                "sub.example23.org",
                true,
        },
        {
                {"||example24.org"},
                "sub.example24.org",
                true,
        },
        {
                {"||example25.org|"},
                "sub.example25.org",
                true,
        },
        {
                {"|example27.org|"},
                "example27.org",
                true,
        },
        {
                {"|example29.org^"},
                "example29.org",
                true,
        },
        {
                {"|https://example31.org/"},
                "example31.org",
                true,
        },
        {
                {"|https://127.0.0.1/"},
                "127.0.0.1",
                true,
        },
        {
                {"|https://0::1/"},
                "::1",
                true,
        },
        {
                {"|https://1:*:1/"},
                "1::1",
                true,
        },
        {
                {"*.0.0.2"},
                "10.0.0.2",
                true,
        },
        {
                {"|192.168.*.1^"},
                "192.168.35.1",
                true,
        },
        {
                {"172.16.*.1:80"},
                "172.16.35.1",
                true,
        },
        {
                {"|172.165.*.1:80^"},
                "172.165.35.1",
                true,
        },
        {
                {"example55.org:8080"},
                "eexample55.org",
                true,
        },
        {
                {"example56.org/^"},
                "eexample56.org",
                true,
        },
        {
                {"example57.org^/"},
                "eexample57.org",
                true,
        },
        {
                {"0.1"},
                "0.1",
                true,
        },
        {
                {"confusing."},
                "veryconfusing.indeed",
                true,
        },
        {
                {"reconfusing."},
                "even.moreconfusing.indeed",
                true,
        },
        {
                {"/.*$/"},
                "example58-1.com",
                true,
        },
        {
                {"/^.*/"},
                "example58-2.com",
                true,
        },
        {
                {"@@||app.adjust.com^|", "||adjust.com^", "@@||app.adjust.com^|$badfilter"},
                "app.adjust.com",
                true,
        },
        {
                {"*$denyallow=com|net", "||evil.com^"},
                "evil.com",
                true,
        },
        {
                {"*$denyallow=com|net", "||evil.com^"},
                "example.com",
                false,
        },
        {
                {"||example.org^$denyallow=sub.example.org"},
                "example.org",
                true,
        },
        {
                {"||example.org^$denyallow=sub.example.org"},
                "sub1.example.org",
                true,
        },
        {
                {"||example.org^$denyallow=sub.example.org"},
                "sub.example.org",
                false,
        },
        {
                {"||example.org^$denyallow=sub.example.org"},
                "sub.sub.example.org",
                false,
        },
        {
                {"@@*$denyallow=com|net", "/.*$/"},
                "example.org",
                false,
        },
        {
                {"@@*$denyallow=com|net", "/.*$/"},
                "example.co.uk",
                false,
        },
        {
                {"@@*$denyallow=com|net", "/.*$/"},
                "example.com",
                true,
        },
        {
                {"@@*$denyallow=com|net", "/.*$/"},
                "example.net",
                true,
        },
};

TEST_F(DnsfilterTest, BasicRulesMatch) {
    for (const auto &entry : BASIC_TEST_DATA) {
        infolog(log, "testing {}", entry.domain);

        std::string file_name = file_by_filter_name(TEST_FILTER_NAME);
        ASSERT_NO_FATAL_FAILURE(clear_filter(file_name));
        for (const std::string &rule : entry.rules) {
            ASSERT_NO_FATAL_FAILURE(add_rule_in_filter(file_name, rule));
        }

        DnsFilter::EngineParams params = {{{10, file_by_filter_name(TEST_FILTER_NAME)}}};
        auto [handle, err_or_warn] = filter.create(params);
        ASSERT_TRUE(handle) << err_or_warn->str();
        std::vector<DnsFilter::Rule> rules = filter.match(handle, {entry.domain});
        if (!rules.empty()) {
            for (const DnsFilter::Rule &r : rules) {
                ASSERT_EQ(r.filter_id, 10);
            }
            DnsFilter::EffectiveRules effective_rules = DnsFilter::get_effective_rules(rules);
            ASSERT_EQ(effective_rules.leftovers.size(), 1);
            const auto *content = std::get_if<DnsFilter::AdblockRuleInfo>(&effective_rules.leftovers[0]->content);
            ASSERT_NE(content, nullptr);
            if (entry.expect_blocked) {
                ASSERT_FALSE(content->props.test(DnsFilter::DARP_EXCEPTION));
            } else {
                ASSERT_TRUE(content->props.test(DnsFilter::DARP_EXCEPTION));
            }
        } else {
            ASSERT_FALSE(entry.expect_blocked);
        }

        filter.destroy(handle);
    }
}

TEST_F(DnsfilterTest, BasicRulesMatchInMemory) {
    std::string filter_data;
    for (const auto &entry : BASIC_TEST_DATA) {
        infolog(log, "testing {}", entry.domain);

        filter_data.clear();
        for (const auto &rule : entry.rules) {
            filter_data += rule;
            filter_data += "\r\n";
        }

        DnsFilter::EngineParams params = {{{10, filter_data, true}}};
        auto [handle, err_or_warn] = filter.create(params);
        ASSERT_TRUE(handle) << err_or_warn->str();

        std::vector<DnsFilter::Rule> rules = filter.match(handle, {entry.domain});
        if (!rules.empty()) {
            for (const DnsFilter::Rule &r : rules) {
                ASSERT_EQ(r.filter_id, 10);
            }
            DnsFilter::EffectiveRules effective_rules = DnsFilter::get_effective_rules(rules);
            ASSERT_EQ(effective_rules.leftovers.size(), 1);
            const auto *content = std::get_if<DnsFilter::AdblockRuleInfo>(&effective_rules.leftovers[0]->content);
            ASSERT_NE(content, nullptr);
            if (entry.expect_blocked) {
                ASSERT_FALSE(content->props.test(DnsFilter::DARP_EXCEPTION));
            } else {
                ASSERT_TRUE(content->props.test(DnsFilter::DARP_EXCEPTION));
            }
        } else {
            ASSERT_FALSE(entry.expect_blocked);
        }

        filter.destroy(handle);
    }
}

TEST_F(DnsfilterTest, BasicRulesNoMatch) {
    struct TestData {
        std::string rule;
        std::string domain;
    };

    const std::vector<TestData> TEST_DATA = {
            {"||*example-1*", "sub.baexaASDFmple-1ab"}, {"||*.example0.*", "example0.com"},
            {
                    "example1.org|",
                    "example1.orgg",
            },
            {
                    "|example2.org",
                    "eexample2.org",
            },
            {
                    "|example3.org|",
                    "eexample3.orgg",
            },
            {
                    "example4.org^",
                    "example4.orgg",
            },
            {
                    "example5.org|",
                    "example5.org.com",
            },
            {
                    "|example6.org",
                    "sub.example6.org",
            },
            {
                    "||example7.org",
                    "eeexample7.org",
            },
            {
                    "://example8.org",
                    "eeexample8.org",
            },
            {
                    "http://example9.org",
                    "eeexample9.org",
            },
            {
                    "example10.org/",
                    "example10.orgg",
            },
            {
                    "|example26.org|",
                    "sub.example26.org",
            },
            {
                    "|example28.org^",
                    "sub.example28.org",
            },
            {
                    "|https://example30.org/",
                    "sub.example30.org",
            },
            {
                    "|0.1^",
                    "10.0.0.1",
            },
            {
                    "|192.168.*.1^",
                    "192.168.35.2",
            },
            {"example56.org:8080", "eexample56.orgg"}, {"|172.165.*.1:80^", "1172.165.35.11"},
            {"example15.org/", "example15.orgg"}, {"example15.org^/", "example15.orgg"},
            {"example15.org/^", "example15.orgg"}, {"||123.123.123.123^", "123.123.123.1234"},
            {"0.1", "10.0.0.1"}, // Exact domain matching => no match
            {"isdotignored.", "isdotignored_no_it_is_not"}, // Dot is not ignored => no match
    };

    for (const TestData &entry : TEST_DATA) {
        ASSERT_NO_FATAL_FAILURE(add_rule_in_filter(file_by_filter_name(TEST_FILTER_NAME), entry.rule));
    }

    DnsFilter::EngineParams params = {{{0, file_by_filter_name(TEST_FILTER_NAME)}}};
    auto [handle, err_or_warn] = filter.create(params);
    ASSERT_TRUE(handle) << err_or_warn->str();

    for (const TestData &entry : TEST_DATA) {
        infolog(log, "testing {}", entry.domain);
        std::vector<DnsFilter::Rule> rules = filter.match(handle, {entry.domain});
        ASSERT_EQ(rules.size(), 0);
    }

    filter.destroy(handle);
}

TEST_F(DnsfilterTest, Wildcard) {
    struct TestData {
        std::string rule;
        std::vector<std::string> domains;
    };

    const std::vector<TestData> TEST_DATA = {
            {
                    "*mple1.org",
                    {
                            "mple1.org",
                            "ample1.org",
                            "xample1.org",
                            "example1.org",
                            "subd.example1.org",
                    },
            },
            {
                    "ex*le2.org",
                    {
                            "exle2.org",
                            "exale2.org",
                            "examle2.org",
                            "example2.org",
                            "subd.example2.org",
                    },
            },
            {
                    "example3.*",
                    {
                            "example3.org",
                            "example3.com",
                            "example3.co.uk",
                            "subd.example3.org",
                    },
            },
    };

    for (const TestData &entry : TEST_DATA) {
        ASSERT_NO_FATAL_FAILURE(add_rule_in_filter(file_by_filter_name(TEST_FILTER_NAME), entry.rule));
    }

    DnsFilter::EngineParams params = {{{0, file_by_filter_name(TEST_FILTER_NAME)}}};
    auto [handle, err_or_warn] = filter.create(params);
    ASSERT_TRUE(handle) << err_or_warn->str();

    for (const TestData &entry : TEST_DATA) {
        for (const std::string &d : entry.domains) {
            infolog(log, "testing {}", d);
            std::vector<DnsFilter::Rule> rules = filter.match(handle, {d});
            ASSERT_EQ(rules.size(), 1);
            const auto *content = std::get_if<DnsFilter::AdblockRuleInfo>(&rules[0].content);
            ASSERT_NE(content, nullptr);
            ASSERT_FALSE(content->props.test(DnsFilter::DARP_EXCEPTION));
            ASSERT_EQ(rules[0].text, entry.rule);
        }
    }

    filter.destroy(handle);
}

TEST_F(DnsfilterTest, Regex) {
    struct TestData {
        std::string rule;
        std::vector<std::string> domains;
    };

    const std::vector<TestData> TEST_DATA = {
            {
                    "/mple1.org/",
                    {
                            "mple1.org",
                            "ample1.org",
                            "xample1.org",
                            "example1.org",
                            "subd.example1.org",
                    },
            },
            {
                    "/mp.*le2.org/",
                    {
                            "Mple2.org",
                            "amptatatale2.org",
                            "XaMpLe2.org",
                            "exAmple2.org",
                            "subd.example2.org",
                    },
            },
            {
                    "/mple[34].org/",
                    {"Mple3.org", "Mple4.org"},
            },
            {
                    "/mple[56]?.org/",
                    {"Mple5.org", "Mple6.org"},
            },
            {
                    "/example-1\\.org/",
                    {"example-1.org", "ExAmPlE-1.OrG"},
            },
            {
                    "/^eXaMpLe-2\\.oRg$/",
                    {"eXaMpLe-2.oRg", "example-2.org"},
            },
            {
                    "/example\\d{4}.org/",
                    {"example0000.org", "example1234.org"},
            },
    };

    for (const TestData &entry : TEST_DATA) {
        ASSERT_NO_FATAL_FAILURE(add_rule_in_filter(file_by_filter_name(TEST_FILTER_NAME), entry.rule));
    }

    DnsFilter::EngineParams params = {{{0, file_by_filter_name(TEST_FILTER_NAME)}}};
    auto [handle, err_or_warn] = filter.create(params);
    ASSERT_TRUE(handle) << err_or_warn->str();
    for (const TestData &entry : TEST_DATA) {
        for (const std::string &d : entry.domains) {
            infolog(log, "testing {}", d);
            std::vector<DnsFilter::Rule> rules = filter.match(handle, {d});
            ASSERT_EQ(rules.size(), 1);
            const auto *content = std::get_if<DnsFilter::AdblockRuleInfo>(&rules[0].content);
            ASSERT_NE(content, nullptr);
            ASSERT_FALSE(content->props.test(DnsFilter::DARP_EXCEPTION));
            ASSERT_EQ(rules[0].text, entry.rule);
        }
    }

    filter.destroy(handle);
}

TEST_F(DnsfilterTest, HostsFileSyntax) {
    struct TestData {
        std::string rule;
        std::vector<std::string> blocked_domains;
        std::string expected_rule;
    };

    const std::vector<TestData> TEST_DATA = {
            {"1.1.1.1 example11.org example12.org example13.org",
                    {
                            "example11.org",
                            "example12.org",
                            "sub.example13.org",
                    }},
            {":: example21.org example22.org example23.org",
                    {
                            "sub.sub.example21.org",
                            "example22.org",
                            "example23.org",
                    }},
            {"::1.1.1.1 example31.org example32.org example33.org",
                    {
                            "example31.org",
                            "example32.org",
                            "example33.org",
                    }},
            {"1:1:1:1:1:1:1:1 example41.org example42.org example43.org",
                    {
                            "example41.org",
                            "sub.example42.org",
                            "example43.org",
                    }},
            {"1:: example51.org example52.org example53.org",
                    {
                            "example51.org",
                            "sub.example52.org",
                            "example53.org",
                    }},
            {"1.1.1.1 example61.org example62.org example63.org #comment",
                    {
                            "example61.org",
                            "example62.org",
                            "sub.example63.org",
                    },
                    {"1.1.1.1 example61.org example62.org example63.org"}},
    };

    for (const TestData &entry : TEST_DATA) {
        ASSERT_NO_FATAL_FAILURE(add_rule_in_filter(file_by_filter_name(TEST_FILTER_NAME), entry.rule));
    }

    DnsFilter::EngineParams params = {{{0, file_by_filter_name(TEST_FILTER_NAME)}}};
    auto [handle, err_or_warn] = filter.create(params);
    ASSERT_TRUE(handle) << err_or_warn->str();

    for (const TestData &entry : TEST_DATA) {
        for (const std::string &d : entry.blocked_domains) {
            infolog(log, "testing {}", d);
            std::vector<DnsFilter::Rule> rules = filter.match(handle, {d});
            ASSERT_EQ(rules.size(), 1);
            if (entry.expected_rule.empty()) {
                ASSERT_EQ(rules[0].text, entry.rule);
            } else {
                ASSERT_EQ(rules[0].text, entry.expected_rule);
            }
            ASSERT_NE(std::get_if<DnsFilter::HostsRuleInfo>(&rules[0].content), nullptr);
        }
    }

    filter.destroy(handle);
}

TEST_F(DnsfilterTest, Badfilter) {
    struct TestData {
        std::vector<std::string> rules;
        std::string domain;
    };

    const std::vector<TestData> TEST_DATA = {
            {
                    {"example1.org", "example1.org$badfilter"},
                    "example1.org",
            },
            {
                    {"example2.org$important", "example2.org$important,badfilter"},
                    "example2.org",
            },
            {
                    {"example3.org$important", "example3.org$badfilter,important"},
                    "example3.org",
            },
            {
                    {"example4.org$dnstype=a", "example4.org$badfilter,dnstype=a"},
                    "example4.org",
            },
            {
                    {"example5.org$dnstype=A", "example5.org$dnstype=A,badfilter"},
                    "example5.org",
            },
    };

    for (const TestData &entry : TEST_DATA) {
        for (const std::string &rule : entry.rules) {
            ASSERT_NO_FATAL_FAILURE(add_rule_in_filter(file_by_filter_name(TEST_FILTER_NAME), rule));
        }
    }

    DnsFilter::EngineParams params = {{{0, file_by_filter_name(TEST_FILTER_NAME)}}};
    auto [handle, err_or_warn] = filter.create(params);
    ASSERT_TRUE(handle) << err_or_warn->str();

    for (const TestData &entry : TEST_DATA) {
        infolog(log, "testing {}", entry.domain);
        std::vector<DnsFilter::Rule> rules = filter.match(handle, {entry.domain, LDNS_RR_TYPE_A});
        ASSERT_EQ(rules.size(), 2);
        DnsFilter::EffectiveRules effective_rules = DnsFilter::get_effective_rules(rules);
        ASSERT_EQ(effective_rules.leftovers.size(), 0);
    }

    filter.destroy(handle);
}

TEST_F(DnsfilterTest, MultipleFilters) {
    struct TestData {
        std::vector<std::string> rules1;
        std::vector<std::string> rules2;
        std::string domain;
        std::string expected_rule;
    };

    const std::vector<TestData> TEST_DATA = {
            {
                    {"example1.org"},
                    {"@@example1.org"},
                    "example1.org",
                    "@@example1.org",
            },
    };

    ag::file::Handle file1 = ag::file::open(file_by_filter_name(TEST_FILTER_NAME + "1"), ag::file::CREAT);
    ag::file::close(file1);
    ag::file::Handle file2 = ag::file::open(file_by_filter_name(TEST_FILTER_NAME + "2"), ag::file::CREAT);
    ag::file::close(file2);

    for (const TestData &entry : TEST_DATA) {
        for (const std::string &rule : entry.rules1) {
            ASSERT_NO_FATAL_FAILURE(add_rule_in_filter(file_by_filter_name(TEST_FILTER_NAME + "1"), rule));
        }
        for (const std::string &rule : entry.rules2) {
            ASSERT_NO_FATAL_FAILURE(add_rule_in_filter(file_by_filter_name(TEST_FILTER_NAME + "2"), rule));
        }
    }

    DnsFilter::EngineParams params
            = {{{0, file_by_filter_name(TEST_FILTER_NAME + "1")}, {1, file_by_filter_name(TEST_FILTER_NAME + "2")}}};
    auto [handle, err_or_warn] = filter.create(params);
    ASSERT_TRUE(handle) << err_or_warn->str();

    for (const TestData &entry : TEST_DATA) {
        infolog(log, "testing {}", entry.domain);
        std::vector<DnsFilter::Rule> rules = filter.match(handle, {entry.domain});
        ASSERT_GT(rules.size(), 0);
        DnsFilter::EffectiveRules effective_rules = DnsFilter::get_effective_rules(rules);
        ASSERT_EQ(effective_rules.leftovers.size(), 1);
        ASSERT_EQ(effective_rules.leftovers[0]->text, entry.expected_rule);
    }

    filter.destroy(handle);

    std::remove(file_by_filter_name(TEST_FILTER_NAME + "1").c_str());
    std::remove(file_by_filter_name(TEST_FILTER_NAME + "2").c_str());
}

TEST_F(DnsfilterTest, RuleSelection) {
    struct TestData {
        std::vector<std::string> rules;
        std::vector<size_t> expected_ids;
    };

    const std::vector<TestData> TEST_DATA = {
            {{"example.org", "example.org$badfilter"}, {}},
            {{"example.org$important", "example.org$badfilter"}, {0}},
            {{"@@example.org", "example.org"}, {0}},
            {{"@@example.org", "example.org", "example.org$important"}, {2}},
            {{"@@example.org", "@@example.org$important", "example.org$important"}, {1}},
            {{"0.0.0.0 example.org", "example.org"}, {0}},
            {{"example.org", "0.0.0.0 example.org"}, {1}},
            {{"example.org", "0.0.0.0 example.org", "0.0.0.1 example.org"}, {1, 2}},
            {{"0.0.0.0 example.org", "example.org", "1::1 example.org"}, {0, 2}},
            {{"0.0.0.0 example.org", "@@example.org"}, {1}},
            {{"0.0.0.0 example.org", "example.org$important"}, {1}},
            {{"||example.com$dnstype=A", "@@||example.com$dnstype=A"}, {1}},
            {{"||example.com$dnstype=A", "@@||example.com$"}, {1}},
            {{"||example.com$dnstype=A,important", "@@||example.com"}, {0}},
            {{"||example.com$dnstype=A", "@@||example.com$dnstype=a,badfilter"}, {0}},
    };

    for (const TestData &entry : TEST_DATA) {
        std::vector<DnsFilter::Rule> rules;
        for (const std::string &text : entry.rules) {
            std::optional<rule_utils::Rule> rule = rule_utils::parse(text, &log);
            ASSERT_TRUE(rule.has_value());
            rules.push_back(std::move(rule->public_part));
        }

        DnsFilter::EffectiveRules effective_rules = DnsFilter::get_effective_rules(rules);
        ASSERT_EQ(effective_rules.leftovers.size(), entry.expected_ids.size());
        for (size_t id : entry.expected_ids) {
            const std::string &wanted_rule = entry.rules[id];
            auto found = std::find_if(effective_rules.leftovers.begin(), effective_rules.leftovers.end(),
                    [&wanted_rule](const DnsFilter::Rule *rule) -> bool {
                        return wanted_rule == rule->text;
                    });
            ASSERT_NE(found, effective_rules.leftovers.end()) << wanted_rule;
            effective_rules.leftovers.erase(found);
        }
        ASSERT_EQ(effective_rules.leftovers.size(), 0);
    }
}

TEST_F(DnsfilterTest, DnstypeModifier) {
    struct TestData {
        std::string_view rule;
        DnsFilter::MatchParam param;
        bool expect_blocked;
    };

    const TestData TEST_DATA[] = {
            {"||example1.com$dnstype=A", {"example1.com", LDNS_RR_TYPE_A}, true},
            {"||example2.com$dnstype=A|TXT", {"example2.com", LDNS_RR_TYPE_TXT}, true},
            {"@@||example3.com$dnstype=CNAME", {"example3.com", LDNS_RR_TYPE_CNAME}, false},
            {"||example4.com$dnstype=~MF", {"example4.com", LDNS_RR_TYPE_MF}, false},
            {"||example5.com$dnstype=A|~WKS", {"example5.com", LDNS_RR_TYPE_WKS}, false},
            {"||example6.com$dnstype=NULL|~HINFO", {"example6.com", LDNS_RR_TYPE_NULL}, true},
            {"||example7.com$dnstype=~ISDN|~NSAP", {"example7.com", LDNS_RR_TYPE_NSAP}, false},
            {"||example8.com$dnstype=~ISDN|~NSAP", {"example8.com", LDNS_RR_TYPE_NXT}, true},
            {"||example9.com$dnstype=CERT|NAPTR", {"example9.com", LDNS_RR_TYPE_NIMLOC}, false},
            {"||example10.com$dnstype=https", {"example10.com", LDNS_RR_TYPE_HTTPS}, true},
            {"/.*$/$dnstype=https", {"example10.com", LDNS_RR_TYPE_HTTPS}, true},
    };

    for (const TestData &entry : TEST_DATA) {
        infolog(log, "testing {}", entry.rule);

        DnsFilter::EngineParams params = {{{10, std::string(entry.rule), true}}};
        auto [handle, err_or_warn] = filter.create(params);
        ASSERT_TRUE(handle) << err_or_warn->str();

        std::vector<DnsFilter::Rule> rules = filter.match(handle, {entry.param});
        if (entry.expect_blocked) {
            ASSERT_EQ(rules.size(), 1);
            ASSERT_EQ(rules[0].text, entry.rule);
        } else {
            if (!rules.empty()) {
                const auto *info = std::get_if<DnsFilter::AdblockRuleInfo>(&rules[0].content);
                ASSERT_NE(info, nullptr);
                ASSERT_TRUE(info->props.test(DnsFilter::DARP_EXCEPTION));
            } else {
                ASSERT_EQ(rules.size(), 0);
            }
        }

        filter.destroy(handle);
    }
}

TEST_F(DnsfilterTest, FileBasedFilterAutoUpdate) {
    const std::string rule1 = "||example.com^\n";
    const std::string rule2 = "||yandex.ru^\n";
    const std::string file_name = "file_based_filter_auto_update.txt";

    std::remove(file_name.c_str());
    ag::file::Handle fd = ag::file::open(file_name, ag::file::CREAT | ag::file::WRONLY);
    ag::file::write(fd, rule1.c_str(), rule1.size());
    ag::file::close(fd);

    DnsFilter::EngineParams params = {{{5, file_name, false}}};
    auto [handle, err_or_warn] = filter.create(params);
    ASSERT_TRUE(handle) << err_or_warn->str();

    std::vector<DnsFilter::Rule> rules = filter.match(handle, {"example.com", LDNS_RR_TYPE_A});
    ASSERT_EQ(rules.size(), 1U);

    fd = ag::file::open(file_name, ag::file::RDWR);

    // need wait at least 1 second after file create
    std::this_thread::sleep_for(Secs(1));

    ag::file::set_position(fd, 0);
    ag::file::write(fd, rule2.c_str(), rule2.size());
    ag::file::write(fd, rule1.c_str(), rule1.size());
    ag::file::close(fd);

    rules.clear();
    rules = filter.match(handle, {"example.com", LDNS_RR_TYPE_A});
    ASSERT_EQ(rules.size(), 1U);
    ASSERT_EQ(rules[0].text + "\n", rule1);

    rules.clear();
    rules = filter.match(handle, {"yandex.ru", LDNS_RR_TYPE_A});
    ASSERT_EQ(rules.size(), 1U);
    ASSERT_EQ(rules[0].text + "\n", rule2);

    std::remove(file_name.c_str());
    filter.destroy(handle);
}

struct CidrTestSample {
    static inline size_t next_idx = 0;

    size_t idx = next_idx++;
    std::string_view ip;
    std::initializer_list<std::string_view> rules;
    std::set<std::string_view> expected_match;

    friend std::ostream &operator<<(std::ostream &os, const CidrTestSample &self) {
        return os << "[" << self.idx << "] ip: " << self.ip;
    }
};


class Cidr : public ::testing::TestWithParam<CidrTestSample> {
protected:
    DnsFilter filter;
    DnsFilter::Handle filter_handle = nullptr;

    void SetUp() override {
        const CidrTestSample &sample = GetParam();

        DnsFilter::EngineParams params = {{{
                .data = ag::utils::join(sample.rules.begin(), sample.rules.end(), "\n"),
                .in_memory = true,
        }}};
        auto [handle, err_or_warn] = filter.create(params);
        ASSERT_NE(handle, nullptr) << err_or_warn->str();
        filter_handle = handle;
    }

    void TearDown() override {
        filter.destroy(filter_handle);
    }
};

TEST_P(Cidr, Match) {
    const CidrTestSample &sample = GetParam();

    std::vector<DnsFilter::Rule> rules = filter.match(filter_handle,
            {
                    .domain = sample.ip,
            });

    std::set<std::string_view> matched_rules;
    for (const auto &r : rules) {
        matched_rules.insert(r.text);
    }

    ASSERT_EQ(sample.expected_match, matched_rules);
}

static const CidrTestSample CIDR_TEST_SAMPLES[] = {
        {
                .ip = "1.1.1.1",
                .rules = {"1.1.1.0/24"},
                .expected_match = {"1.1.1.0/24"},
        },
        {
                .ip = "1.1.1.1",
                .rules = {"1.1.1.42/24"},
                .expected_match = {"1.1.1.42/24"},
        },
        {
                .ip = "1.1.1.0",
                .rules = {"1.1.1.0/24"},
                .expected_match = {"1.1.1.0/24"},
        },
        {
                .ip = "1.1.1.1",
                .rules = {"1.1.1.1/32"},
                .expected_match = {"1.1.1.1/32"},
        },
        {
                .ip = "1.1.1.1",
                .rules = {"@@1.1.1.1/32", "1.0.0.0/8"},
                .expected_match = {"@@1.1.1.1/32", "1.0.0.0/8"},
        },
        {
                .ip = "1.1.1.1",
                .rules = {"1.1.1.1/32", "@@1.0.0.0/8"},
                .expected_match = {"1.1.1.1/32", "@@1.0.0.0/8"},
        },

        {
                .ip = "1.1.2.0",
                .rules = {"1.1.1.0/24"},
        },
        {
                .ip = "1.1.1.2",
                .rules = {"1.1.1.1/32"},
        },

        {
                .ip = "feed::beef",
                .rules = {"feed::beef/128"},
                .expected_match = {"feed::beef/128"},
        },
        {
                .ip = "feed::beef",
                .rules = {"feed::be00/120"},
                .expected_match = {"feed::be00/120"},
        },

        {
                .ip = "feed::beef",
                .rules = {"feed::be00/120", "@@feed::bee0/124"},
                .expected_match = {"feed::be00/120", "@@feed::bee0/124"},
        },

        {
                .ip = "feed::feef",
                .rules = {"feed::be00/120"},
        },
        {
                .ip = "feed::beef",
                .rules = {"feed::be00/128"},
        },
};

INSTANTIATE_TEST_SUITE_P(DnsFilter, Cidr, testing::ValuesIn(CIDR_TEST_SAMPLES));

} // namespace ag::dns::dnsfilter::test

TEST(RuleValidator, IsValidRule) {
    ASSERT_TRUE(ag::dns::DnsFilter::is_valid_rule("||*.example.*"));
    ASSERT_TRUE(ag::dns::DnsFilter::is_valid_rule("||*example*"));
    ASSERT_TRUE(ag::dns::DnsFilter::is_valid_rule("example.org"));
    ASSERT_TRUE(ag::dns::DnsFilter::is_valid_rule("exampleorg"));
    ASSERT_TRUE(ag::dns::DnsFilter::is_valid_rule("example-org"));
    ASSERT_TRUE(ag::dns::DnsFilter::is_valid_rule("example_org"));
    ASSERT_TRUE(ag::dns::DnsFilter::is_valid_rule("_exampleorg"));
    ASSERT_TRUE(ag::dns::DnsFilter::is_valid_rule("ttp"));
    ASSERT_TRUE(ag::dns::DnsFilter::is_valid_rule("ab"));
    ASSERT_TRUE(ag::dns::DnsFilter::is_valid_rule("@@example.org"));
    ASSERT_TRUE(ag::dns::DnsFilter::is_valid_rule("example.org$important"));
    ASSERT_TRUE(ag::dns::DnsFilter::is_valid_rule("@@example.org$important"));
    ASSERT_TRUE(ag::dns::DnsFilter::is_valid_rule("|example.org"));
    ASSERT_TRUE(ag::dns::DnsFilter::is_valid_rule("example.org|"));
    ASSERT_TRUE(ag::dns::DnsFilter::is_valid_rule("|example.org|"));
    ASSERT_TRUE(ag::dns::DnsFilter::is_valid_rule(".example"));
    ASSERT_TRUE(ag::dns::DnsFilter::is_valid_rule("example."));
    ASSERT_TRUE(ag::dns::DnsFilter::is_valid_rule("*example.org"));
    ASSERT_TRUE(ag::dns::DnsFilter::is_valid_rule("||example.org|"));
    ASSERT_TRUE(ag::dns::DnsFilter::is_valid_rule("||example.org^"));
    ASSERT_TRUE(ag::dns::DnsFilter::is_valid_rule("||example.org"));
    ASSERT_TRUE(ag::dns::DnsFilter::is_valid_rule("/example.org/"));
    ASSERT_TRUE(ag::dns::DnsFilter::is_valid_rule("/example.org/$badfilter"));
    ASSERT_TRUE(ag::dns::DnsFilter::is_valid_rule("/ex[a]?mple.org/"));
    ASSERT_TRUE(ag::dns::DnsFilter::is_valid_rule("/ex[ab]mple.org/"));
    ASSERT_TRUE(ag::dns::DnsFilter::is_valid_rule("example.org$badfilter"));
    ASSERT_TRUE(ag::dns::DnsFilter::is_valid_rule("-ad-banner."));
    ASSERT_TRUE(ag::dns::DnsFilter::is_valid_rule("-ad-unit/"));
    ASSERT_TRUE(ag::dns::DnsFilter::is_valid_rule("-ad-unit^"));
    ASSERT_TRUE(ag::dns::DnsFilter::is_valid_rule("-ad-unit/^"));
    ASSERT_TRUE(ag::dns::DnsFilter::is_valid_rule("-ad-unit^/"));
    ASSERT_TRUE(ag::dns::DnsFilter::is_valid_rule("||adminpromotion.com^"));
    ASSERT_TRUE(ag::dns::DnsFilter::is_valid_rule("||travelstool.com^"));
    ASSERT_TRUE(ag::dns::DnsFilter::is_valid_rule("example.org:8080"));
    ASSERT_TRUE(ag::dns::DnsFilter::is_valid_rule("//example.org:8080"));
    ASSERT_TRUE(ag::dns::DnsFilter::is_valid_rule("://example.org"));
    ASSERT_TRUE(ag::dns::DnsFilter::is_valid_rule("://example.org/"));
    ASSERT_TRUE(ag::dns::DnsFilter::is_valid_rule("http://example.org/"));
    ASSERT_TRUE(ag::dns::DnsFilter::is_valid_rule("https://example.org|"));
    ASSERT_TRUE(ag::dns::DnsFilter::is_valid_rule("ws://example.org|"));
    ASSERT_TRUE(ag::dns::DnsFilter::is_valid_rule("example.org^|"));
    ASSERT_TRUE(ag::dns::DnsFilter::is_valid_rule("example.org|^"));
    ASSERT_TRUE(ag::dns::DnsFilter::is_valid_rule("|example.org^"));
    ASSERT_TRUE(ag::dns::DnsFilter::is_valid_rule("|https://example31.org/"));
    ASSERT_TRUE(ag::dns::DnsFilter::is_valid_rule("/127.0.0.1/"));
    ASSERT_TRUE(ag::dns::DnsFilter::is_valid_rule("/12:34:56:78::90/"));
    ASSERT_TRUE(ag::dns::DnsFilter::is_valid_rule("123.123.123.123"));
    ASSERT_TRUE(ag::dns::DnsFilter::is_valid_rule("12:34:56:78::90"));
    ASSERT_TRUE(ag::dns::DnsFilter::is_valid_rule("123.123.123.123$badfilter"));
    ASSERT_TRUE(ag::dns::DnsFilter::is_valid_rule("12:34:56:78::90$badfilter"));
    ASSERT_TRUE(ag::dns::DnsFilter::is_valid_rule("@@123.123.123.123"));
    ASSERT_TRUE(ag::dns::DnsFilter::is_valid_rule("@@12:34:56:78::90"));
    ASSERT_TRUE(ag::dns::DnsFilter::is_valid_rule("0.0.0.0"));
    ASSERT_TRUE(ag::dns::DnsFilter::is_valid_rule("::1"));
    ASSERT_TRUE(ag::dns::DnsFilter::is_valid_rule("|123.123.123.123^"));
    ASSERT_TRUE(ag::dns::DnsFilter::is_valid_rule("|12:34:56:78::90^"));
    ASSERT_TRUE(ag::dns::DnsFilter::is_valid_rule("||123.123.123.123^"));
    ASSERT_TRUE(ag::dns::DnsFilter::is_valid_rule("||12:34:56:78::90^"));
    ASSERT_TRUE(ag::dns::DnsFilter::is_valid_rule("http://123.123.123.123"));
    ASSERT_TRUE(ag::dns::DnsFilter::is_valid_rule("http://12:34:56:78::90^"));
    ASSERT_TRUE(ag::dns::DnsFilter::is_valid_rule("https://123.123.123.123"));
    ASSERT_TRUE(ag::dns::DnsFilter::is_valid_rule("https://12:34:56:78::90^"));
    ASSERT_TRUE(ag::dns::DnsFilter::is_valid_rule("172.16.*.1"));
    ASSERT_TRUE(ag::dns::DnsFilter::is_valid_rule("172.16.*.1:80"));
    ASSERT_TRUE(ag::dns::DnsFilter::is_valid_rule("|172.16.*.1:80^"));
    ASSERT_TRUE(ag::dns::DnsFilter::is_valid_rule("1.1.1.0/24"));
    ASSERT_TRUE(ag::dns::DnsFilter::is_valid_rule("@@1.1.1.0/24"));
    ASSERT_TRUE(ag::dns::DnsFilter::is_valid_rule("example.org$dnstype=A"));
    ASSERT_TRUE(ag::dns::DnsFilter::is_valid_rule("example.org$dnstype=AAAA"));
    ASSERT_TRUE(ag::dns::DnsFilter::is_valid_rule("example.org$dnstype=~A"));
    ASSERT_TRUE(ag::dns::DnsFilter::is_valid_rule("example.org$dnstype=A|AAAA"));
    ASSERT_TRUE(ag::dns::DnsFilter::is_valid_rule("example.org$dnstype=A|~AAAA"));
    ASSERT_TRUE(ag::dns::DnsFilter::is_valid_rule("@@example.org$dnstype=A"));
    ASSERT_TRUE(ag::dns::DnsFilter::is_valid_rule("@@example.org$dnstype"));
    ASSERT_TRUE(ag::dns::DnsFilter::is_valid_rule("@@example.org$dnstype=a"));
    ASSERT_TRUE(ag::dns::DnsFilter::is_valid_rule("||4.3.2.1.in-addr.arpa.^$dnsrewrite=REFUSED;PTR;example.net."));
    ASSERT_TRUE(ag::dns::DnsFilter::is_valid_rule("example.org$dnsrewrite=NOERROR;A;1.2.3.4"));
    ASSERT_TRUE(ag::dns::DnsFilter::is_valid_rule("example.org$dnsrewrite=SERVFAIL;CNAME;example.org"));
    ASSERT_TRUE(ag::dns::DnsFilter::is_valid_rule("example.org$dnsrewrite=NOERROR;MX;42 example.mail"));
    ASSERT_TRUE(ag::dns::DnsFilter::is_valid_rule("example.org$dnsrewrite=FORMERR;TXT;hello_world"));
    ASSERT_TRUE(ag::dns::DnsFilter::is_valid_rule("example.org$dnsrewrite=NXDOMAIN;;"));
    ASSERT_TRUE(ag::dns::DnsFilter::is_valid_rule("example.org$dnsrewrite=NOERROR;SVCB;1 ."));
    ASSERT_TRUE(ag::dns::DnsFilter::is_valid_rule("example.org$dnsrewrite=NOERROR;HTTPS;1 example.net alpn=h3"));
    ASSERT_TRUE(ag::dns::DnsFilter::is_valid_rule("example.org$dnsrewrite"));
    ASSERT_TRUE(ag::dns::DnsFilter::is_valid_rule("@@example.org$dnsrewrite=1.2.3.4"));
    ASSERT_TRUE(ag::dns::DnsFilter::is_valid_rule("@@example.org$dnsrewrite=abcd::1234"));
    ASSERT_TRUE(ag::dns::DnsFilter::is_valid_rule("@@example.org$dnsrewrite=example.net"));
    ASSERT_TRUE(ag::dns::DnsFilter::is_valid_rule("@@example.org$dnsrewrite=NOTIMPL"));
    ASSERT_TRUE(ag::dns::DnsFilter::is_valid_rule("@@example.org$dnsrewrite"));
    ASSERT_TRUE(ag::dns::DnsFilter::is_valid_rule("*$dnstype=HTTPS"));
    ASSERT_TRUE(ag::dns::DnsFilter::is_valid_rule("$dnstype=HTTPS"));
    ASSERT_TRUE(ag::dns::DnsFilter::is_valid_rule("/.*/$dnstype=HTTPS"));
    ASSERT_TRUE(ag::dns::DnsFilter::is_valid_rule("/.*$/$dnstype=HTTPS"));
    ASSERT_TRUE(ag::dns::DnsFilter::is_valid_rule("*$dnsrewrite"));
    ASSERT_TRUE(ag::dns::DnsFilter::is_valid_rule("$dnsrewrite"));
    ASSERT_TRUE(ag::dns::DnsFilter::is_valid_rule("/.*/$dnsrewrite"));
    ASSERT_TRUE(ag::dns::DnsFilter::is_valid_rule("$denyallow=com|net"));
    ASSERT_TRUE(ag::dns::DnsFilter::is_valid_rule("$denyallow=example.org"));
    ASSERT_FALSE(ag::dns::DnsFilter::is_valid_rule(""));
    ASSERT_FALSE(ag::dns::DnsFilter::is_valid_rule("!example.com"));
    ASSERT_FALSE(ag::dns::DnsFilter::is_valid_rule("#example.com"));
    ASSERT_FALSE(ag::dns::DnsFilter::is_valid_rule("@example"));
    ASSERT_FALSE(ag::dns::DnsFilter::is_valid_rule("||||example"));
    ASSERT_FALSE(ag::dns::DnsFilter::is_valid_rule("||example$unknown"));
    ASSERT_FALSE(ag::dns::DnsFilter::is_valid_rule("||example$important,important"));
    ASSERT_FALSE(ag::dns::DnsFilter::is_valid_rule(
            "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee.example.org"));
    ASSERT_FALSE(ag::dns::DnsFilter::is_valid_rule(
            "eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee."
            "eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee."
            "eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee."
            "eeee.eeee.org"));
    ASSERT_FALSE(ag::dns::DnsFilter::is_valid_rule("?example.org"));
    ASSERT_FALSE(ag::dns::DnsFilter::is_valid_rule("^"));
    ASSERT_FALSE(ag::dns::DnsFilter::is_valid_rule("*"));
    ASSERT_FALSE(ag::dns::DnsFilter::is_valid_rule("/[example.org/"));
    ASSERT_FALSE(ag::dns::DnsFilter::is_valid_rule("&admeld_"));
    ASSERT_FALSE(ag::dns::DnsFilter::is_valid_rule("+advertorial."));
    ASSERT_FALSE(ag::dns::DnsFilter::is_valid_rule("?ad_partner="));
    ASSERT_FALSE(ag::dns::DnsFilter::is_valid_rule("@@||flashx.tv/js/xfs.js"));
    ASSERT_FALSE(ag::dns::DnsFilter::is_valid_rule("example.com/page"));
    ASSERT_FALSE(ag::dns::DnsFilter::is_valid_rule("example.com^some"));
    ASSERT_FALSE(ag::dns::DnsFilter::is_valid_rule("example.com|some"));
    ASSERT_FALSE(ag::dns::DnsFilter::is_valid_rule("example.com/^page"));
    ASSERT_FALSE(ag::dns::DnsFilter::is_valid_rule("|||example.com"));
    ASSERT_FALSE(ag::dns::DnsFilter::is_valid_rule("example.com^|^"));
    ASSERT_FALSE(ag::dns::DnsFilter::is_valid_rule("example.com//"));
    ASSERT_FALSE(ag::dns::DnsFilter::is_valid_rule("/example.com"));
    ASSERT_FALSE(ag::dns::DnsFilter::is_valid_rule("///example.com"));
    ASSERT_FALSE(ag::dns::DnsFilter::is_valid_rule("333.333.333.333 example.org"));
    ASSERT_FALSE(ag::dns::DnsFilter::is_valid_rule("45:67 example.org"));
    ASSERT_FALSE(ag::dns::DnsFilter::is_valid_rule("example.org$dnstype"));
    ASSERT_FALSE(ag::dns::DnsFilter::is_valid_rule("example.org$dnstypee"));
    ASSERT_FALSE(ag::dns::DnsFilter::is_valid_rule("example.org$dnstype="));
    ASSERT_FALSE(ag::dns::DnsFilter::is_valid_rule("example.org$dnstype=~"));
    ASSERT_FALSE(ag::dns::DnsFilter::is_valid_rule("example.org$dnstype=OOPS"));
    ASSERT_FALSE(ag::dns::DnsFilter::is_valid_rule("example.org$dnstype=A|A"));
    ASSERT_FALSE(ag::dns::DnsFilter::is_valid_rule("example.org$dnstype=A|~A"));
    ASSERT_FALSE(ag::dns::DnsFilter::is_valid_rule("||example.org^$dnsrewrite=bad;syntax"));
    ASSERT_FALSE(ag::dns::DnsFilter::is_valid_rule("||example.org^$dnsrewrite=nonexisting;nonexisting;nonexisting"));
    ASSERT_FALSE(ag::dns::DnsFilter::is_valid_rule("||example.org^$dnsrewrite=NOERROR;nonexisting;nonexisting"));
    ASSERT_FALSE(ag::dns::DnsFilter::is_valid_rule("||example.org^$dnsrewrite=NOERROR;A;badip"));
    ASSERT_FALSE(ag::dns::DnsFilter::is_valid_rule("||example.org^$dnsrewrite=NOERROR;AAAA;badip"));
    ASSERT_FALSE(ag::dns::DnsFilter::is_valid_rule("||example.org^$dnsrewrite=NOERROR;AAAA;127.0.0.1"));
    ASSERT_FALSE(ag::dns::DnsFilter::is_valid_rule("||example.org^$dnsrewrite=NOERROR;;127.0.0.1"));
    ASSERT_FALSE(ag::dns::DnsFilter::is_valid_rule("||example.org^$dnsrewrite=REFUSED;PTR;example.net."));
    ASSERT_FALSE(ag::dns::DnsFilter::is_valid_rule("||4.3.2.1.in-addr.arpa.^$dnsrewrite=REFUSED;PTR;example.net"));
    ASSERT_FALSE(ag::dns::DnsFilter::is_valid_rule("||4.3.2.1.in-addr.arpa^$dnsrewrite=REFUSED;PTR;example.net."));
    ASSERT_FALSE(ag::dns::DnsFilter::is_valid_rule("4.3.2.1.in-addr.arpa.^$dnsrewrite=REFUSED;PTR;example.net."));
    ASSERT_FALSE(ag::dns::DnsFilter::is_valid_rule("||4.3.2.1.in-addr.arpa.$dnsrewrite=REFUSED;PTR;example.net."));
    ASSERT_FALSE(ag::dns::DnsFilter::is_valid_rule("4.3.2.1.in-addr.arpa.$dnsrewrite=REFUSED;PTR;example.net."));
    ASSERT_FALSE(ag::dns::DnsFilter::is_valid_rule("example.org$dnsrewrite=NOERROR;MX;65536 example.mail"));
    ASSERT_FALSE(ag::dns::DnsFilter::is_valid_rule("example.org$dnsrewrite=NOERROR;MX;-42 example.mail"));
    ASSERT_FALSE(ag::dns::DnsFilter::is_valid_rule("example.org$dnsrewrite=NOERROR;MX;42 ***xxx@@@1!!"));
    ASSERT_FALSE(ag::dns::DnsFilter::is_valid_rule("example.org$dnsrewrite=NOERROR;MX;xx example.mail"));
    ASSERT_FALSE(ag::dns::DnsFilter::is_valid_rule("example.org$dnsrewrite=NOERROR;HTTPS;65536 example.net alpn=h3"));
    ASSERT_FALSE(ag::dns::DnsFilter::is_valid_rule("example.org$dnsrewrite=NOERROR;HTTPS;1 xxx@@@111 alpn=h3"));
    ASSERT_FALSE(ag::dns::DnsFilter::is_valid_rule("example.org$dnsrewrite=NOERROR;SVCB;1 . nonexisting=foo"));
    ASSERT_FALSE(ag::dns::DnsFilter::is_valid_rule("example.org$dnsrewrite=NOERROR;SVCB;example.org nonexisting=foo"));
    ASSERT_FALSE(ag::dns::DnsFilter::is_valid_rule("::"));
    ASSERT_FALSE(ag::dns::DnsFilter::is_valid_rule("*a"));
    ASSERT_FALSE(ag::dns::DnsFilter::is_valid_rule("a*"));
    ASSERT_FALSE(ag::dns::DnsFilter::is_valid_rule(".*"));
    ASSERT_FALSE(ag::dns::DnsFilter::is_valid_rule("example.org$denyallow"));
    ASSERT_FALSE(ag::dns::DnsFilter::is_valid_rule("example.org$denyallow="));
}
