#include <gtest/gtest.h>
#include <numeric>
#include <string>
#include <ag_file.h>
#include <ag_sys.h>
#include "common/logger.h"
#include "common/utils.h"
#include <dnsfilter.h>
#include <rule_utils.h>

class dnsfilter_test : public ::testing::Test {
protected:

    ag::dnsfilter filter;
    ag::file::handle file;
    ag::Logger log{"dnsfilter_test"};

    const std::string TEST_FILTER_NAME = "dnsfilter_test";

    void SetUp() override {
        ag::Logger::set_log_level(ag::LogLevel::LOG_LEVEL_TRACE);
        file = ag::file::open(file_by_filter_name(TEST_FILTER_NAME), ag::file::CREAT|ag::file::RDONLY);
        ASSERT_TRUE(ag::file::is_valid(file)) << ag::sys::error_string(ag::sys::error_code());
        ag::file::close(file);
    }

    void TearDown() override {
        std::remove(file_by_filter_name(TEST_FILTER_NAME).data());
    }

    static void add_rule_in_filter(std::string_view filter, std::string_view rule) {
        ag::file::handle file = ag::file::open(std::string(filter), ag::file::WRONLY);
        ASSERT_TRUE(ag::file::is_valid(file)) << ag::sys::error_string(ag::sys::error_code());
        ASSERT_TRUE(ag::file::get_size(file) >= 0) << ag::sys::error_string(ag::sys::error_code());
        ag::file::set_position(file, ag::file::get_size(file));
        EXPECT_EQ(ag::file::write(file, rule.data(), rule.length()), rule.length());
        EXPECT_EQ(ag::file::write(file, "\n", 1), 1);
        ag::file::close(file);
    }

    static std::string file_by_filter_name(std::string filter) {
        return filter + ".txt";
    }

    static void check_rdf(const ldns_rdf *rdf, ldns_rdf_type type, const char *value) {
        ASSERT_EQ(ldns_rdf_get_type(rdf), type);
        auto rdf_str = ag::AllocatedPtr<char>(ldns_rdf2str(rdf));
        ASSERT_STREQ(rdf_str.get(), value);
    }
};


TEST_F(dnsfilter_test, successful_rule_parsing) {
    struct test_data {
        std::string text;
        rule_utils::rule expected_rule;
    };

    static constexpr auto make_rule =
            [] (ag::dnsfilter::adblock_rule_info::props_set p = 0) -> ag::dnsfilter::rule {
                ag::dnsfilter::rule r = { .content = ag::dnsfilter::adblock_rule_info{ p } };
                return r;
            };

    const test_data TEST_DATA[] =
        {
            { "||*.example.*", { make_rule(), rule_utils::rule::MMID_SHORTCUTS_AND_REGEX } },
            { "||*example*", { make_rule(), rule_utils::rule::MMID_SHORTCUTS_AND_REGEX } },
            { "example.org", { make_rule(), rule_utils::rule::MMID_EXACT } },
            { "exampleorg", { make_rule(), rule_utils::rule::MMID_EXACT } },
            { "example-org", { make_rule(), rule_utils::rule::MMID_EXACT } },
            { "example_org", { make_rule(), rule_utils::rule::MMID_EXACT } },
            { "_exampleorg", { make_rule(), rule_utils::rule::MMID_EXACT } },
            { "ttp", { make_rule(), rule_utils::rule::MMID_EXACT } },
            { "ab", { make_rule(), rule_utils::rule::MMID_EXACT } }, // It is NOT too wide
            { "@@example.org", { make_rule(1 << ag::dnsfilter::DARP_EXCEPTION), rule_utils::rule::MMID_SHORTCUTS } },
            { "example.org$important", { make_rule(1 << ag::dnsfilter::DARP_IMPORTANT), rule_utils::rule::MMID_SHORTCUTS } },
            { "@@example.org$important", { make_rule((1 << ag::dnsfilter::DARP_EXCEPTION) | (1 << ag::dnsfilter::DARP_IMPORTANT)), rule_utils::rule::MMID_SHORTCUTS } },
            { "|example.org", { make_rule(), rule_utils::rule::MMID_SHORTCUTS_AND_REGEX } },
            { "example.org|", { make_rule(), rule_utils::rule::MMID_SHORTCUTS_AND_REGEX } },
            { "|example.org|", { make_rule(), rule_utils::rule::MMID_EXACT } },
            { ".example", { make_rule(), rule_utils::rule::MMID_SHORTCUTS } },
            { "example.", { make_rule(), rule_utils::rule::MMID_SHORTCUTS } },
            { "*example.org", { make_rule(), rule_utils::rule::MMID_SHORTCUTS } },
            { "||example.org|", { make_rule(), rule_utils::rule::MMID_SUBDOMAINS } },
            { "||example.org^", { make_rule(), rule_utils::rule::MMID_SUBDOMAINS } },
            { "||example.org", { make_rule(), rule_utils::rule::MMID_SHORTCUTS_AND_REGEX } },
            { "/example.org/", { make_rule(), rule_utils::rule::MMID_SHORTCUTS_AND_REGEX } },
            { "/example.org/$badfilter", { make_rule(1 << ag::dnsfilter::DARP_BADFILTER) } },
            { "/ex[a]?mple.org/", { make_rule(), rule_utils::rule::MMID_REGEX } },
            { "/ex[ab]mple.org/", { make_rule(), rule_utils::rule::MMID_SHORTCUTS_AND_REGEX } },
            { "example.org$badfilter", { make_rule(1 << ag::dnsfilter::DARP_BADFILTER) } },
            { "-ad-banner.", { make_rule(), rule_utils::rule::MMID_SHORTCUTS } },
            { "-ad-unit/", { make_rule(), rule_utils::rule::MMID_SHORTCUTS_AND_REGEX } },
            { "-ad-unit^", { make_rule(), rule_utils::rule::MMID_SHORTCUTS_AND_REGEX } },
            { "-ad-unit/^", { make_rule(), rule_utils::rule::MMID_SHORTCUTS_AND_REGEX } },
            { "-ad-unit^/", { make_rule(), rule_utils::rule::MMID_SHORTCUTS_AND_REGEX } },
            { "||adminpromotion.com^", { make_rule(), rule_utils::rule::MMID_SUBDOMAINS } },
            { "||travelstool.com^", { make_rule(), rule_utils::rule::MMID_SUBDOMAINS } },
            { "example.org:8080", { make_rule(), rule_utils::rule::MMID_SHORTCUTS_AND_REGEX } },
            { "//example.org:8080", { make_rule(), rule_utils::rule::MMID_SUBDOMAINS } },
            { "://example.org", { make_rule(), rule_utils::rule::MMID_SHORTCUTS_AND_REGEX } },
            { "://example.org/", { make_rule(), rule_utils::rule::MMID_SUBDOMAINS } },
            { "http://example.org/", { make_rule(), rule_utils::rule::MMID_SUBDOMAINS } },
            { "https://example.org|", { make_rule(), rule_utils::rule::MMID_SUBDOMAINS } },
            { "ws://example.org|", { make_rule(), rule_utils::rule::MMID_SUBDOMAINS } },
            { "example.org^|", { make_rule(), rule_utils::rule::MMID_SHORTCUTS_AND_REGEX } },
            { "example.org|^", { make_rule(), rule_utils::rule::MMID_SHORTCUTS_AND_REGEX } },
            { "|example.org^", { make_rule(), rule_utils::rule::MMID_EXACT } },
            { "|https://example31.org/", { make_rule(), rule_utils::rule::MMID_EXACT } },
            { "/127.0.0.1/", { make_rule(), rule_utils::rule::MMID_SHORTCUTS_AND_REGEX } },
            { "/12:34:56:78::90/", { make_rule(), rule_utils::rule::MMID_SHORTCUTS_AND_REGEX } },
            { "123.123.123.123", { make_rule(), rule_utils::rule::MMID_SHORTCUTS } },
            { "12:34:56:78::90", { make_rule(), rule_utils::rule::MMID_SHORTCUTS } },
            { "123.123.123.123$badfilter", { make_rule(1 << ag::dnsfilter::DARP_BADFILTER), rule_utils::rule::MMID_EXACT } },
            { "12:34:56:78::90$badfilter", { make_rule(1 << ag::dnsfilter::DARP_BADFILTER), rule_utils::rule::MMID_EXACT } },
            { "@@123.123.123.123", { make_rule(1 << ag::dnsfilter::DARP_EXCEPTION), rule_utils::rule::MMID_SHORTCUTS } },
            { "@@12:34:56:78::90", { make_rule(1 << ag::dnsfilter::DARP_EXCEPTION), rule_utils::rule::MMID_SHORTCUTS } },
            { "0.0.0.0", { make_rule(), rule_utils::rule::MMID_SHORTCUTS } },
            { "::1", { make_rule(), rule_utils::rule::MMID_SHORTCUTS } },
            { "|123.123.123.123^", { make_rule(), rule_utils::rule::MMID_EXACT } },
            { "|12:34:56:78::90^", { make_rule(), rule_utils::rule::MMID_EXACT } },
            { "||123.123.123.123^", { make_rule(), rule_utils::rule::MMID_SUBDOMAINS } },
            { "||12:34:56:78::90^", { make_rule(), rule_utils::rule::MMID_SUBDOMAINS } },
            { "http://123.123.123.123", { make_rule(), rule_utils::rule::MMID_SHORTCUTS_AND_REGEX } },
            { "http://12:34:56:78::90^", { make_rule(), rule_utils::rule::MMID_SUBDOMAINS } },
            { "https://123.123.123.123", { make_rule(), rule_utils::rule::MMID_SHORTCUTS_AND_REGEX } },
            { "https://12:34:56:78::90^", { make_rule(), rule_utils::rule::MMID_SUBDOMAINS } },
            { "172.16.*.1", { make_rule(), rule_utils::rule::MMID_SHORTCUTS } },
            { "172.16.*.1:80", { make_rule(), rule_utils::rule::MMID_SHORTCUTS_AND_REGEX } },
            { "|172.16.*.1:80^", { make_rule(), rule_utils::rule::MMID_SHORTCUTS_AND_REGEX } },
            { "example.org$dnstype=A", { make_rule(1 << ag::dnsfilter::DARP_DNSTYPE), rule_utils::rule::MMID_SHORTCUTS } },
            { "example.org$dnstype=AAAA", { make_rule(1 << ag::dnsfilter::DARP_DNSTYPE), rule_utils::rule::MMID_SHORTCUTS } },
            { "example.org$dnstype=~A", { make_rule(1 << ag::dnsfilter::DARP_DNSTYPE), rule_utils::rule::MMID_SHORTCUTS } },
            { "example.org$dnstype=A|AAAA", { make_rule(1 << ag::dnsfilter::DARP_DNSTYPE), rule_utils::rule::MMID_SHORTCUTS } },
            { "example.org$dnstype=A|~AAAA", { make_rule(1 << ag::dnsfilter::DARP_DNSTYPE), rule_utils::rule::MMID_SHORTCUTS } },
            { "@@example.org$dnstype=A", { make_rule((1 << ag::dnsfilter::DARP_EXCEPTION) | (1 << ag::dnsfilter::DARP_DNSTYPE)), rule_utils::rule::MMID_SHORTCUTS } },
            { "@@example.org$dnstype", { make_rule((1 << ag::dnsfilter::DARP_EXCEPTION) | (1 << ag::dnsfilter::DARP_DNSTYPE)), rule_utils::rule::MMID_SHORTCUTS } },
            { "@@example.org$dnstype=a", { make_rule((1 << ag::dnsfilter::DARP_EXCEPTION) | (1 << ag::dnsfilter::DARP_DNSTYPE)), rule_utils::rule::MMID_SHORTCUTS } },
            { "||4.3.2.1.in-addr.arpa.^$dnsrewrite=REFUSED;PTR;example.net.", { make_rule((1 << ag::dnsfilter::DARP_DNSREWRITE)), rule_utils::rule::MMID_SUBDOMAINS } },
            { "example.org$dnsrewrite=NOERROR;A;1.2.3.4", { make_rule((1 << ag::dnsfilter::DARP_DNSREWRITE)), rule_utils::rule::MMID_SHORTCUTS } },
            { "example.org$dnsrewrite=SERVFAIL;CNAME;example.org", { make_rule((1 << ag::dnsfilter::DARP_DNSREWRITE)), rule_utils::rule::MMID_SHORTCUTS } },
            { "example.org$dnsrewrite=NOERROR;MX;42 example.mail", { make_rule((1 << ag::dnsfilter::DARP_DNSREWRITE)), rule_utils::rule::MMID_SHORTCUTS } },
            { "example.org$dnsrewrite=FORMERR;TXT;hello_world", { make_rule((1 << ag::dnsfilter::DARP_DNSREWRITE)), rule_utils::rule::MMID_SHORTCUTS } },
            { "example.org$dnsrewrite=NXDOMAIN;;", { make_rule((1 << ag::dnsfilter::DARP_DNSREWRITE)), rule_utils::rule::MMID_SHORTCUTS } },
            { "example.org$dnsrewrite=NOERROR;SVCB;1 .", { make_rule((1 << ag::dnsfilter::DARP_DNSREWRITE)), rule_utils::rule::MMID_SHORTCUTS } },
            { "example.org$dnsrewrite=NOERROR;HTTPS;1 example.net alpn=h3", { make_rule((1 << ag::dnsfilter::DARP_DNSREWRITE)), rule_utils::rule::MMID_SHORTCUTS } },
            { "example.org$dnsrewrite", { make_rule((1 << ag::dnsfilter::DARP_DNSREWRITE)), rule_utils::rule::MMID_SHORTCUTS } },
            { "@@example.org$dnsrewrite=1.2.3.4", { make_rule((1 << ag::dnsfilter::DARP_DNSREWRITE) | (1 << ag::dnsfilter::DARP_EXCEPTION)), rule_utils::rule::MMID_SHORTCUTS } },
            { "@@example.org$dnsrewrite=abcd::1234", { make_rule((1 << ag::dnsfilter::DARP_DNSREWRITE) | (1 << ag::dnsfilter::DARP_EXCEPTION)), rule_utils::rule::MMID_SHORTCUTS } },
            { "@@example.org$dnsrewrite=example.net", { make_rule((1 << ag::dnsfilter::DARP_DNSREWRITE) | (1 << ag::dnsfilter::DARP_EXCEPTION)), rule_utils::rule::MMID_SHORTCUTS } },
            { "@@example.org$dnsrewrite=NOTIMPL", { make_rule((1 << ag::dnsfilter::DARP_DNSREWRITE) | (1 << ag::dnsfilter::DARP_EXCEPTION)), rule_utils::rule::MMID_SHORTCUTS } },
            { "@@example.org$dnsrewrite", { make_rule((1 << ag::dnsfilter::DARP_DNSREWRITE) | (1 << ag::dnsfilter::DARP_EXCEPTION)), rule_utils::rule::MMID_SHORTCUTS } },
            { "*$dnstype=HTTPS", { make_rule(1 << ag::dnsfilter::DARP_DNSTYPE), rule_utils::rule::MMID_SHORTCUTS } },
            { "$dnstype=HTTPS", { make_rule(1 << ag::dnsfilter::DARP_DNSTYPE), rule_utils::rule::MMID_SHORTCUTS } },
            { "/.*/$dnstype=HTTPS", { make_rule(1 << ag::dnsfilter::DARP_DNSTYPE), rule_utils::rule::MMID_REGEX } },
            { "/.*$/$dnstype=HTTPS", { make_rule(1 << ag::dnsfilter::DARP_DNSTYPE), rule_utils::rule::MMID_REGEX } },
            { "*$dnsrewrite", { make_rule((1 << ag::dnsfilter::DARP_DNSREWRITE)), rule_utils::rule::MMID_SHORTCUTS } },
            { "$dnsrewrite", { make_rule((1 << ag::dnsfilter::DARP_DNSREWRITE)), rule_utils::rule::MMID_SHORTCUTS } },
            { "/.*/$dnsrewrite", { make_rule((1 << ag::dnsfilter::DARP_DNSREWRITE)), rule_utils::rule::MMID_REGEX } },
        };

    for (const test_data &entry : TEST_DATA) {
        infolog(log, "testing {}", entry.text);
        std::optional<rule_utils::rule> rule = rule_utils::parse(entry.text, &log);
        ASSERT_TRUE(rule.has_value());
        const auto *content = std::get_if<ag::dnsfilter::adblock_rule_info>(&rule->public_part.content);
        ASSERT_NE(content, nullptr);
        ASSERT_EQ(content->props, std::get<ag::dnsfilter::adblock_rule_info>(entry.expected_rule.public_part.content).props);
        ASSERT_EQ(rule->match_method, entry.expected_rule.match_method);
    }
}

TEST_F(dnsfilter_test, successful_host_syntax_rule_parsing) {
    struct test_data {
        std::string text;
        rule_utils::rule expected_rule;
    };

    const test_data TEST_DATA[] =
        {
            { "0.0.0.0 example.org",
                { { .content = ag::dnsfilter::etc_hosts_rule_info{ "0.0.0.0" } }, rule_utils::rule::MMID_SUBDOMAINS } },
            { "1:1:: example.org",
                { { .content = ag::dnsfilter::etc_hosts_rule_info{ "1:1::" } }, rule_utils::rule::MMID_SUBDOMAINS } },
            { "1:1:1:1:1:1:1:1 example.org",
                { { .content = ag::dnsfilter::etc_hosts_rule_info{ "1:1:1:1:1:1:1:1" } }, rule_utils::rule::MMID_SUBDOMAINS } },
            { "::1:1 example.org",
                { { .content = ag::dnsfilter::etc_hosts_rule_info{ "::1:1" } }, rule_utils::rule::MMID_SUBDOMAINS } },
            { "::FFFF:1.1.1.1 example.org",
                { { .content = ag::dnsfilter::etc_hosts_rule_info{ "::FFFF:1.1.1.1" } }, rule_utils::rule::MMID_SUBDOMAINS } },
            { "0.0.0.0 example.org #comment",
                    { { .content = ag::dnsfilter::etc_hosts_rule_info{ "0.0.0.0" } }, rule_utils::rule::MMID_SUBDOMAINS } },
        };

    for (const test_data &entry : TEST_DATA) {
        infolog(log, "testing {}", entry.text);
        std::optional<rule_utils::rule> rule = rule_utils::parse(entry.text, &log);
        ASSERT_TRUE(rule.has_value());
        const auto *content = std::get_if<ag::dnsfilter::etc_hosts_rule_info>(&rule->public_part.content);
        ASSERT_NE(content, nullptr);
        ASSERT_EQ(content->ip, std::get<ag::dnsfilter::etc_hosts_rule_info>(entry.expected_rule.public_part.content).ip);
        ASSERT_EQ(rule->match_method, entry.expected_rule.match_method);
    }
}

TEST_F(dnsfilter_test, wrong_rule_parsing) {
    const std::string TEST_DATA[] =
        {
            "",
            "!example.com",
            "#example.com",
            "@example",
            "||||example",
            "||example$unknown",
            "||example$important,important",
            "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee.example.org",
            "eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.eeee.org",
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
        };

    for (const std::string &entry : TEST_DATA) {
        infolog(log, "testing {}", entry);
        std::optional<rule_utils::rule> rule = rule_utils::parse(entry, &log);
        ASSERT_FALSE(rule.has_value());
    }
}

struct basic_test_data {
    std::vector<std::string> rules;
    std::string domain;
    bool expect_blocked;
};

const std::vector<basic_test_data> BASIC_TEST_DATA = {
        { { "||*example-1*" }, "sub.baexample-1ab", true, },
        { { "||*.example0.*" }, "sub.example0.com", true, },
        { { "example1.org" }, "example1.org", true, },
        { { "example2.org", "@@example2.org" }, "example2.org", false, },
        { { "example3.org", "@@example3.org", "example3.org$important" }, "example3.org", true, },
        { { "example4.org", "@@example4.org", "example4.org$important", "@@example4.org$important" }, "example4.org", false, },
        { { "example5.org^" }, "example5.org", true, },
        { { "||example6.org|" }, "example6.org", true, },
        { { "*mple7.org" }, "example7.org", true, },
        { { "ExAmPlE8.org" }, "example8.org", true, },
        { { "example9.org" }, "EXAMPLE9.org", true, },
        { { ".example10.org" }, "sub.example10.org", true },
        { { "http://example11.org" }, "example11.org", true, },
        { { "http://example111.org" }, "example111.org1", true, },
        { { "http://example1111.org" }, "sub.example1111.org1", true, },
        { { "://example12.org" }, "example12.org", true, },
        { { "//example13.org" }, "sub.example13.org", true, },
        { { "example15.org/" }, "example15.org", true, },
        { { "example16.org/" }, "eexample16.org", true, },
        { { "example17.org:8080" }, "example17.org", true, },
        { { "example18.org|" }, "eexample18.org", true, },
        { { "example19.org^" }, "eexample19.org", true, },
        { { "|example20.org" }, "example20.orgg", true, },
        { { "example21." }, "eexample21.org", true, },
        { { "example22.org|" }, "sub.example22.org", true, },
        { { "example23.org^" }, "sub.example23.org", true, },
        { { "||example24.org" }, "sub.example24.org", true, },
        { { "||example25.org|" }, "sub.example25.org", true, },
        { { "|example27.org|" }, "example27.org", true, },
        { { "|example29.org^" }, "example29.org", true, },
        { { "|https://example31.org/" }, "example31.org", true, },
        { { "|https://127.0.0.1/" }, "127.0.0.1", true, },
        { { "|https://0::1/" }, "::1", true, },
        { { "|https://1:*:1/" }, "1::1", true, },
        { { "*.0.0.2" }, "10.0.0.2", true, },
        { { "|192.168.*.1^" }, "192.168.35.1", true, },
        { { "172.16.*.1:80" }, "172.16.35.1", true, },
        { { "|172.165.*.1:80^" }, "172.165.35.1", true, },
        { { "example55.org:8080" }, "eexample55.org", true, },
        { { "example56.org/^" }, "eexample56.org", true, },
        { { "example57.org^/" }, "eexample57.org", true, },
        { { "0.1" }, "0.1", true, },
        { { "confusing." }, "veryconfusing.indeed", true, },
        { { "reconfusing." }, "even.moreconfusing.indeed", true, },
        { { "/.*$/" }, "example58.com", true, },
        { { "/^/" }, "example59.com", true, },
        { { "/$/" }, "example60.com", true, },
};

TEST_F(dnsfilter_test, basic_rules_match) {
    for (const auto &entry : BASIC_TEST_DATA) {
        infolog(log, "testing {}", entry.domain);

        for (const std::string &rule : entry.rules) {
            ASSERT_NO_FATAL_FAILURE(add_rule_in_filter(file_by_filter_name(TEST_FILTER_NAME), rule));
        }

        ag::dnsfilter::engine_params params = { { { 10, file_by_filter_name(TEST_FILTER_NAME) } } };
        auto [handle, err_or_warn] = filter.create(params);
        ASSERT_TRUE(handle) << *err_or_warn;
        std::vector<ag::dnsfilter::rule> rules = filter.match(handle, { entry.domain });
        ASSERT_GT(rules.size(), 0);
        for (const ag::dnsfilter::rule &r : rules) {
            ASSERT_EQ(r.filter_id, 10);
        }
        ag::dnsfilter::effective_rules effective_rules = ag::dnsfilter::get_effective_rules(rules);
        ASSERT_EQ(effective_rules.leftovers.size(), 1);
        const auto *content = std::get_if<ag::dnsfilter::adblock_rule_info>(&effective_rules.leftovers[0]->content);
        ASSERT_NE(content, nullptr);
        if (entry.expect_blocked) {
            ASSERT_FALSE(content->props.test(ag::dnsfilter::DARP_EXCEPTION));
        } else {
            ASSERT_TRUE(content->props.test(ag::dnsfilter::DARP_EXCEPTION));
        }

        filter.destroy(handle);
    }
}

TEST_F(dnsfilter_test, basic_rules_match_in_memory) {
    std::string filter_data;
    for (const auto &entry : BASIC_TEST_DATA) {
        infolog(log, "testing {}", entry.domain);

        for (const auto &rule : entry.rules) {
            filter_data += rule;
            filter_data += "\r\n";
        }

        ag::dnsfilter::engine_params params = { { { 10, filter_data, true } } };
        auto [handle, err_or_warn] = filter.create(params);
        ASSERT_TRUE(handle) << *err_or_warn;

        std::vector<ag::dnsfilter::rule> rules = filter.match(handle, { entry.domain });
        ASSERT_GT(rules.size(), 0);
        for (const ag::dnsfilter::rule &r : rules) {
            ASSERT_EQ(r.filter_id, 10);
        }
        ag::dnsfilter::effective_rules effective_rules = ag::dnsfilter::get_effective_rules(rules);
        ASSERT_EQ(effective_rules.leftovers.size(), 1);
        const auto *content = std::get_if<ag::dnsfilter::adblock_rule_info>(&effective_rules.leftovers[0]->content);
        ASSERT_NE(content, nullptr);
        if (entry.expect_blocked) {
            ASSERT_FALSE(content->props.test(ag::dnsfilter::DARP_EXCEPTION));
        } else {
            ASSERT_TRUE(content->props.test(ag::dnsfilter::DARP_EXCEPTION));
        }

        filter.destroy(handle);
    }
}

TEST_F(dnsfilter_test, basic_rules_no_match) {
    struct test_data {
        std::string rule;
        std::string domain;
    };

    const std::vector<test_data> TEST_DATA =
        {
            { "||*example-1*", "sub.baexaASDFmple-1ab" },
            { "||*.example0.*", "example0.com" },
            { "example1.org|", "example1.orgg", },
            { "|example2.org", "eexample2.org", },
            { "|example3.org|", "eexample3.orgg", },
            { "example4.org^", "example4.orgg", },
            { "example5.org|", "example5.org.com", },
            { "|example6.org", "sub.example6.org", },
            { "||example7.org", "eeexample7.org", },
            { "://example8.org", "eeexample8.org", },
            { "http://example9.org", "eeexample9.org", },
            { "example10.org/", "example10.orgg", },
            { "|example26.org|", "sub.example26.org", },
            { "|example28.org^", "sub.example28.org", },
            { "|https://example30.org/", "sub.example30.org", },
            { "|0.1^", "10.0.0.1", },
            { "|192.168.*.1^", "192.168.35.2",},
            { "example56.org:8080", "eexample56.orgg"},
            { "|172.165.*.1:80^", "1172.165.35.11"},
            { "example15.org/", "example15.orgg"},
            { "example15.org^/", "example15.orgg"},
            { "example15.org/^", "example15.orgg"},
            { "||123.123.123.123^", "123.123.123.1234" },
            { "0.1" , "10.0.0.1" }, // Exact domain matching => no match
            { "isdotignored." , "isdotignored_no_it_is_not" }, // Dot is not ignored => no match
        };

    for (const test_data &entry : TEST_DATA) {
        ASSERT_NO_FATAL_FAILURE(add_rule_in_filter(file_by_filter_name(TEST_FILTER_NAME), entry.rule));
    }

    ag::dnsfilter::engine_params params = { { { 0, file_by_filter_name(TEST_FILTER_NAME) } } };
    auto [handle, err_or_warn] = filter.create(params);
    ASSERT_TRUE(handle) << *err_or_warn;

    for (const test_data &entry : TEST_DATA) {
        infolog(log, "testing {}", entry.domain);
        std::vector<ag::dnsfilter::rule> rules = filter.match(handle, { entry.domain });
        ASSERT_EQ(rules.size(), 0);
    }

    filter.destroy(handle);
}

TEST_F(dnsfilter_test, wildcard) {
    struct test_data {
        std::string rule;
        std::vector<std::string> domains;
    };

    const std::vector<test_data> TEST_DATA =
        {
            { "*mple1.org", { "mple1.org", "ample1.org", "xample1.org", "example1.org", "subd.example1.org", }, },
            { "ex*le2.org", { "exle2.org", "exale2.org", "examle2.org", "example2.org", "subd.example2.org", }, },
            { "example3.*", { "example3.org", "example3.com", "example3.co.uk", "subd.example3.org", }, },
        };

    for (const test_data &entry : TEST_DATA) {
        ASSERT_NO_FATAL_FAILURE(add_rule_in_filter(file_by_filter_name(TEST_FILTER_NAME), entry.rule));
    }

    ag::dnsfilter::engine_params params = { { { 0, file_by_filter_name(TEST_FILTER_NAME) } } };
    auto [handle, err_or_warn] = filter.create(params);
    ASSERT_TRUE(handle) << *err_or_warn;

    for (const test_data &entry : TEST_DATA) {
        for (const std::string &d : entry.domains) {
            infolog(log, "testing {}", d);
            std::vector<ag::dnsfilter::rule> rules = filter.match(handle, { d });
            ASSERT_EQ(rules.size(), 1);
            const auto *content = std::get_if<ag::dnsfilter::adblock_rule_info>(&rules[0].content);
            ASSERT_NE(content, nullptr);
            ASSERT_FALSE(content->props.test(ag::dnsfilter::DARP_EXCEPTION));
            ASSERT_EQ(rules[0].text, entry.rule);
        }
    }

    filter.destroy(handle);
}

TEST_F(dnsfilter_test, regex) {
    struct test_data {
        std::string rule;
        std::vector<std::string> domains;
    };

    const std::vector<test_data> TEST_DATA =
        {
            { "/mple1.org/", { "mple1.org", "ample1.org", "xample1.org", "example1.org", "subd.example1.org", }, },
            { "/mp.*le2.org/", { "Mple2.org", "amptatatale2.org", "XaMpLe2.org", "exAmple2.org", "subd.example2.org", }, },
            { "/mple[34].org/", { "Mple3.org", "Mple4.org" }, },
            { "/mple[56]?.org/", { "Mple5.org", "Mple6.org" }, },
            { "/example-1\\.org/", { "example-1.org", "ExAmPlE-1.OrG"}, },
            { "/^eXaMpLe-2\\.oRg$/", { "eXaMpLe-2.oRg", "example-2.org" }, },
            { "/example\\d{4}.org/", { "example0000.org", "example1234.org" }, },
        };

    for (const test_data &entry : TEST_DATA) {
        ASSERT_NO_FATAL_FAILURE(add_rule_in_filter(file_by_filter_name(TEST_FILTER_NAME), entry.rule));
    }

    ag::dnsfilter::engine_params params = { { { 0, file_by_filter_name(TEST_FILTER_NAME) } } };
    auto [handle, err_or_warn] = filter.create(params);
    ASSERT_TRUE(handle) << *err_or_warn;
    for (const test_data &entry : TEST_DATA) {
        for (const std::string &d : entry.domains) {
            infolog(log, "testing {}", d);
            std::vector<ag::dnsfilter::rule> rules = filter.match(handle, { d });
            ASSERT_EQ(rules.size(), 1);
            const auto *content = std::get_if<ag::dnsfilter::adblock_rule_info>(&rules[0].content);
            ASSERT_NE(content, nullptr);
            ASSERT_FALSE(content->props.test(ag::dnsfilter::DARP_EXCEPTION));
            ASSERT_EQ(rules[0].text, entry.rule);
        }
    }

    filter.destroy(handle);
}

TEST_F(dnsfilter_test, hosts_file_syntax) {
    struct test_data {
        std::string rule;
        std::vector<std::string> blocked_domains;
        std::string expected_rule;
    };

    const std::vector<test_data> TEST_DATA =
        {
            { "1.1.1.1 example11.org example12.org example13.org",
                { "example11.org", "example12.org", "sub.example13.org", } },
            { ":: example21.org example22.org example23.org",
                { "sub.sub.example21.org", "example22.org", "example23.org", } },
            { "::1.1.1.1 example31.org example32.org example33.org",
                { "example31.org", "example32.org", "example33.org", } },
            { "1:1:1:1:1:1:1:1 example41.org example42.org example43.org",
                { "example41.org", "sub.example42.org", "example43.org", } },
            { "1:: example51.org example52.org example53.org",
                { "example51.org", "sub.example52.org", "example53.org", } },
            { "1.1.1.1 example61.org example62.org example63.org #comment",
                { "example61.org", "example62.org", "sub.example63.org", },
                { "1.1.1.1 example61.org example62.org example63.org" } },
        };


    for (const test_data &entry : TEST_DATA) {
        ASSERT_NO_FATAL_FAILURE(add_rule_in_filter(file_by_filter_name(TEST_FILTER_NAME), entry.rule));
    }

    ag::dnsfilter::engine_params params = { { { 0, file_by_filter_name(TEST_FILTER_NAME) } } };
    auto [handle, err_or_warn] = filter.create(params);
    ASSERT_TRUE(handle) << *err_or_warn;

    for (const test_data &entry : TEST_DATA) {
        for (const std::string &d : entry.blocked_domains) {
            infolog(log, "testing {}", d);
            std::vector<ag::dnsfilter::rule> rules = filter.match(handle, { d });
            ASSERT_EQ(rules.size(), 1);
            if (entry.expected_rule.empty()) {
                ASSERT_EQ(rules[0].text, entry.rule);
            } else {
                ASSERT_EQ(rules[0].text, entry.expected_rule);
            }
            ASSERT_NE(std::get_if<ag::dnsfilter::etc_hosts_rule_info>(&rules[0].content), nullptr);
        }
    }

    filter.destroy(handle);
}

TEST_F(dnsfilter_test, badfilter) {
    struct test_data {
        std::vector<std::string> rules;
        std::string domain;
    };

    const std::vector<test_data> TEST_DATA =
        {
            { { "example1.org", "example1.org$badfilter" }, "example1.org", },
            { { "example2.org$important", "example2.org$important,badfilter" }, "example2.org", },
            { { "example3.org$important", "example3.org$badfilter,important" }, "example3.org", },
            { { "example4.org$dnstype=a", "example4.org$badfilter,dnstype=a" }, "example4.org", },
            { { "example5.org$dnstype=A", "example5.org$dnstype=A,badfilter" }, "example5.org", },
        };

    for (const test_data &entry : TEST_DATA) {
        for (const std::string &rule : entry.rules) {
            ASSERT_NO_FATAL_FAILURE(add_rule_in_filter(file_by_filter_name(TEST_FILTER_NAME), rule));
        }
    }

    ag::dnsfilter::engine_params params = { { { 0, file_by_filter_name(TEST_FILTER_NAME) } } };
    auto [handle, err_or_warn] = filter.create(params);
    ASSERT_TRUE(handle) << *err_or_warn;

    for (const test_data &entry : TEST_DATA) {
        infolog(log, "testing {}", entry.domain);
        std::vector<ag::dnsfilter::rule> rules = filter.match(handle, { entry.domain, LDNS_RR_TYPE_A });
        ASSERT_EQ(rules.size(), 2);
        ag::dnsfilter::effective_rules effective_rules = ag::dnsfilter::get_effective_rules(rules);
        ASSERT_EQ(effective_rules.leftovers.size(), 0);
    }

    filter.destroy(handle);
}

TEST_F(dnsfilter_test, multifilters) {
    struct test_data {
        std::vector<std::string> rules1;
        std::vector<std::string> rules2;
        std::string domain;
        std::string expected_rule;
    };

    const std::vector<test_data> TEST_DATA =
        {
            { { "example1.org" }, { "@@example1.org" }, "example1.org", "@@example1.org", },
        };

    ag::file::handle file1 = ag::file::open(file_by_filter_name(TEST_FILTER_NAME + "1"), ag::file::CREAT);
    ag::file::close(file1);
    ag::file::handle file2 = ag::file::open(file_by_filter_name(TEST_FILTER_NAME + "2"), ag::file::CREAT);
    ag::file::close(file2);

    for (const test_data &entry : TEST_DATA) {
        for (const std::string &rule : entry.rules1) {
            ASSERT_NO_FATAL_FAILURE(add_rule_in_filter(file_by_filter_name(TEST_FILTER_NAME + "1"), rule));
        }
        for (const std::string &rule : entry.rules2) {
            ASSERT_NO_FATAL_FAILURE(add_rule_in_filter(file_by_filter_name(TEST_FILTER_NAME + "2"), rule));
        }
    }

    ag::dnsfilter::engine_params params = { { { 0, file_by_filter_name(TEST_FILTER_NAME + "1") }, { 1, file_by_filter_name(TEST_FILTER_NAME + "2") } } };
    auto [handle, err_or_warn] = filter.create(params);
    ASSERT_TRUE(handle) << *err_or_warn;

    for (const test_data &entry : TEST_DATA) {
        infolog(log, "testing {}", entry.domain);
        std::vector<ag::dnsfilter::rule> rules = filter.match(handle, { entry.domain });
        ASSERT_GT(rules.size(), 0);
        ag::dnsfilter::effective_rules effective_rules = ag::dnsfilter::get_effective_rules(rules);
        ASSERT_EQ(effective_rules.leftovers.size(), 1);
        ASSERT_EQ(effective_rules.leftovers[0]->text, entry.expected_rule);
    }

    filter.destroy(handle);

    std::remove(file_by_filter_name(TEST_FILTER_NAME + "1").c_str());
    std::remove(file_by_filter_name(TEST_FILTER_NAME + "2").c_str());
}

TEST_F(dnsfilter_test, rule_selection) {
    struct test_data {
        std::vector<std::string> rules;
        std::vector<size_t> expected_ids;
    };

    const std::vector<test_data> TEST_DATA =
        {
            { { "example.org", "example.org$badfilter" }, {} },
            { { "example.org$important", "example.org$badfilter" }, { 0 } },
            { { "@@example.org", "example.org" }, { 0 } },
            { { "@@example.org", "example.org", "example.org$important" }, { 2 } },
            { { "@@example.org", "@@example.org$important", "example.org$important" }, { 1 } },
            { { "0.0.0.0 example.org", "example.org" }, { 0 } },
            { { "example.org", "0.0.0.0 example.org" }, { 1 } },
            { { "example.org", "0.0.0.0 example.org", "0.0.0.1 example.org" }, { 1, 2 } },
            { { "0.0.0.0 example.org", "example.org", "1::1 example.org" }, { 0, 2 } },
            { { "0.0.0.0 example.org", "@@example.org" }, { 1 } },
            { { "0.0.0.0 example.org", "example.org$important" }, { 1 } },
            { { "||example.com$dnstype=A", "@@||example.com$dnstype=A" }, { 1 } },
            { { "||example.com$dnstype=A", "@@||example.com$" }, { 1 } },
            { { "||example.com$dnstype=A,important", "@@||example.com" }, { 0 } },
            { { "||example.com$dnstype=A", "@@||example.com$dnstype=a,badfilter" }, { 0 } },
        };

    for (const test_data &entry : TEST_DATA) {
        std::vector<ag::dnsfilter::rule> rules;
        for (const std::string &text : entry.rules) {
            std::optional<rule_utils::rule> rule = rule_utils::parse(text, &log);
            ASSERT_TRUE(rule.has_value());
            rules.push_back(std::move(rule->public_part));
        }

        ag::dnsfilter::effective_rules effective_rules = ag::dnsfilter::get_effective_rules(rules);
        ASSERT_EQ(effective_rules.leftovers.size(), entry.expected_ids.size());
        for (size_t id : entry.expected_ids) {
            const std::string &wanted_rule = entry.rules[id];
            auto found = std::find_if(effective_rules.leftovers.begin(), effective_rules.leftovers.end(),
                [&wanted_rule] (const ag::dnsfilter::rule *rule) -> bool {
                    return wanted_rule == rule->text;
                });
            ASSERT_NE(found, effective_rules.leftovers.end()) << wanted_rule;
            effective_rules.leftovers.erase(found);
        }
        ASSERT_EQ(effective_rules.leftovers.size(), 0);
    }
}

TEST_F(dnsfilter_test, dnstype_modifier) {
    struct test_data {
        std::string_view rule;
        ag::dnsfilter::match_param param;
        bool expect_blocked;
    };

    const test_data TEST_DATA[] = {
            { "||example1.com$dnstype=A", { "example1.com", LDNS_RR_TYPE_A }, true },
            { "||example2.com$dnstype=A|TXT", { "example2.com", LDNS_RR_TYPE_TXT }, true },
            { "@@||example3.com$dnstype=CNAME", { "example3.com", LDNS_RR_TYPE_CNAME }, false },
            { "||example4.com$dnstype=~MF", { "example4.com", LDNS_RR_TYPE_MF }, false },
            { "||example5.com$dnstype=A|~WKS", { "example5.com", LDNS_RR_TYPE_WKS }, false },
            { "||example6.com$dnstype=NULL|~HINFO", { "example6.com", LDNS_RR_TYPE_NULL }, true },
            { "||example7.com$dnstype=~ISDN|~NSAP", { "example7.com", LDNS_RR_TYPE_NSAP }, false },
            { "||example8.com$dnstype=~ISDN|~NSAP", { "example8.com", LDNS_RR_TYPE_NXT }, true },
            { "||example9.com$dnstype=CERT|NAPTR", { "example9.com", LDNS_RR_TYPE_NIMLOC }, false },
            { "||example10.com$dnstype=https", { "example10.com", LDNS_RR_TYPE_HTTPS }, true },
            { "/.*$/$dnstype=https", { "example10.com", LDNS_RR_TYPE_HTTPS }, true },
    };

    for (const test_data &entry : TEST_DATA) {
        infolog(log, "testing {}", entry.rule);

        ag::dnsfilter::engine_params params = { { { 10, std::string(entry.rule), true } } };
        auto[handle, err_or_warn] = filter.create(params);
        ASSERT_TRUE(handle) << *err_or_warn;

        std::vector<ag::dnsfilter::rule> rules = filter.match(handle, { entry.param });
        if (entry.expect_blocked) {
            ASSERT_EQ(rules.size(), 1);
            ASSERT_EQ(rules[0].text, entry.rule);
        } else {
            if (!rules.empty()) {
                const auto *info = std::get_if<ag::dnsfilter::adblock_rule_info>(&rules[0].content);
                ASSERT_NE(info, nullptr);
                ASSERT_TRUE(info->props.test(ag::dnsfilter::DARP_EXCEPTION));
            } else {
                ASSERT_EQ(rules.size(), 0);
            }
        }

        filter.destroy(handle);
    }
}

TEST_F(dnsfilter_test, file_based_filter_auto_update) {
    const std::string rule1 = "||example.com^\n";
    const std::string rule2 = "||yandex.ru^\n";
    const std::string file_name = "file_based_filter_auto_update.txt";

    std::remove(file_name.c_str());
    ag::file::handle fd = ag::file::open(file_name, ag::file::CREAT | ag::file::WRONLY);
    ag::file::write(fd, rule1.c_str(), rule1.size());
    ag::file::close(fd);

    ag::dnsfilter::engine_params params = {{{5, file_name, false}}};
    auto[handle, err_or_warn] = filter.create(params);
    ASSERT_TRUE(handle) << *err_or_warn;

    std::vector<ag::dnsfilter::rule> rules = filter.match(handle, {"example.com", LDNS_RR_TYPE_A});
    ASSERT_EQ(rules.size(), 1U);

    fd = ag::file::open(file_name, ag::file::RDWR);

    //need wait at least 1 second after file create
    std::this_thread::sleep_for(std::chrono::seconds(1));

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
