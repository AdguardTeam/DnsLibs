#include <gtest/gtest.h>
#include <numeric>
#include <string>
#include <ag_file.h>
#include <ag_utils.h>
#include <ag_sys.h>
#include <ag_logger.h>
#include <dnsfilter.h>
#include <spdlog/spdlog.h>
#include <rule_utils.h>


class dnsfilter_test : public ::testing::Test {
protected:

    ag::dnsfilter filter;
    ag::dnsfilter::handle handle;
    ag::file::handle file;

    const std::string TEST_FILTER_NAME = "dnsfilter_test";

    void SetUp() override {
        ag::set_default_log_level(ag::TRACE);
        file = ag::file::open(file_by_filter_name(TEST_FILTER_NAME), ag::file::CREAT|ag::file::RDONLY);
        ASSERT_TRUE(ag::file::is_valid(file)) << ag::sys::error_string(ag::sys::error_code());
        ag::file::close(file);
    }

    void TearDown() override {
        std::remove(file_by_filter_name(TEST_FILTER_NAME).data());
    }

    static void add_rule_in_filter(std::string_view filter, std::string_view rule) {
        ag::file::handle file = ag::file::open(filter, ag::file::WRONLY);
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
};


TEST_F(dnsfilter_test, successful_rule_parsing) {
    struct test_data {
        std::string text;
        rule_utils::rule expected_rule;
    };

    const test_data TEST_DATA[] =
        {
            { "example.org", { {}, rule_utils::rule::MMID_DOMAINS } },
            { "@@example.org", { { .props = { 1 << ag::dnsfilter::RP_EXCEPTION } }, rule_utils::rule::MMID_DOMAINS } },
            { "example.org$important", { { .props = { 1 << ag::dnsfilter::RP_IMPORTANT } }, rule_utils::rule::MMID_DOMAINS } },
            { "@@example.org$important", { { .props = { (1 << ag::dnsfilter::RP_EXCEPTION) | (1 << ag::dnsfilter::RP_IMPORTANT) } }, rule_utils::rule::MMID_DOMAINS } },
            { "|example.org", { {}, rule_utils::rule::MMID_SHORTCUTS_AND_REGEX } },
            { "example.org|", { {}, rule_utils::rule::MMID_SHORTCUTS_AND_REGEX } },
            { "|example.org|", { {}, rule_utils::rule::MMID_DOMAINS } },
            { "example", { {}, rule_utils::rule::MMID_SHORTCUTS } },
            { ".example", { {}, rule_utils::rule::MMID_SHORTCUTS } },
            { "example.", { {}, rule_utils::rule::MMID_SHORTCUTS } },
            { "*example.org", { {}, rule_utils::rule::MMID_SHORTCUTS } },
            { "||example.org|", { {}, rule_utils::rule::MMID_DOMAINS } },
            { "||example.org^", { {}, rule_utils::rule::MMID_DOMAINS } },
            { "||example.org", { {}, rule_utils::rule::MMID_SHORTCUTS_AND_REGEX } },
            { "/example.org/", { {}, rule_utils::rule::MMID_SHORTCUTS_AND_REGEX } },
            { "/ex[a]?mple.org/", { {}, rule_utils::rule::MMID_REGEX } },
            { "example.org$badfilter", { { .props = { 1 << ag::dnsfilter::RP_BADFILTER } } } },
            { "-ad-banner.", { {} , rule_utils::rule::MMID_SHORTCUTS } },
            { "-ad-unit/", { {} , rule_utils::rule::MMID_SHORTCUTS } },
            { "||adminpromotion.com^", { {}, rule_utils::rule::MMID_DOMAINS } },
            { "||travelstool.com^", { {}, rule_utils::rule::MMID_DOMAINS } },
            { "example.org:8080", { {}, rule_utils::rule::MMID_DOMAINS } },
            { "//example.org:8080", { {}, rule_utils::rule::MMID_DOMAINS } },
            { "://example.org", { {}, rule_utils::rule::MMID_DOMAINS } },
            { "://example.org/", { {}, rule_utils::rule::MMID_DOMAINS } },
            { "http://example.org/", { {}, rule_utils::rule::MMID_DOMAINS } },
            { "https://example.org|", { {}, rule_utils::rule::MMID_DOMAINS } },
            { "ws://example.org|", { {}, rule_utils::rule::MMID_DOMAINS } },
            { "example.org^|", { {}, rule_utils::rule::MMID_SHORTCUTS_AND_REGEX } },
            { "example.org|^", { {}, rule_utils::rule::MMID_SHORTCUTS_AND_REGEX } },
        };

    ag::logger log = ag::create_logger("dnsfilter_test");

    for (const test_data &entry : TEST_DATA) {
        SPDLOG_INFO("testing {}", entry.text);
        std::optional<rule_utils::rule> rule = rule_utils::parse(entry.text, &log);
        ASSERT_TRUE(rule.has_value());
        ASSERT_EQ(rule->public_part.props, entry.expected_rule.public_part.props);
        ASSERT_FALSE(rule->public_part.ip.has_value());
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
                { { .props = {}, .ip = std::make_optional("0.0.0.0") }, rule_utils::rule::MMID_DOMAINS } },
            { "1:1:: example.org",
                { { .props = {}, .ip = std::make_optional("1:1::") }, rule_utils::rule::MMID_DOMAINS } },
            { "1:1:1:1:1:1:1:1 example.org",
                { { .props = {}, .ip = std::make_optional("1:1:1:1:1:1:1:1") }, rule_utils::rule::MMID_DOMAINS } },
            { "::1:1 example.org",
                { { .props = {}, .ip = std::make_optional("::1:1") }, rule_utils::rule::MMID_DOMAINS } },
            { "::FFFF:1.1.1.1 example.org",
                { { .props = {}, .ip = std::make_optional("::FFFF:1.1.1.1") }, rule_utils::rule::MMID_DOMAINS } },
        };

    ag::logger log = ag::create_logger("dnsfilter_test");

    for (const test_data &entry : TEST_DATA) {
        SPDLOG_INFO("testing {}", entry.text);
        std::optional<rule_utils::rule> rule = rule_utils::parse(entry.text, &log);
        ASSERT_TRUE(rule.has_value());
        ASSERT_EQ(rule->public_part.props, entry.expected_rule.public_part.props);
        ASSERT_EQ(rule->public_part.ip, entry.expected_rule.public_part.ip);
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
            "example.com:8o",
            "example.com:111111",
            "hhtp://example.com:111111",
            "example.com//",
            "/example.com",
            "///example.com",
        };

    ag::logger log = ag::create_logger("dnsfilter_test");

    for (const std::string &entry : TEST_DATA) {
        SPDLOG_INFO("testing {}", entry);
        std::optional<rule_utils::rule> rule = rule_utils::parse(entry, &log);
        ASSERT_FALSE(rule.has_value());
    }
}

TEST_F(dnsfilter_test, basic_rules_match) {
    struct test_data {
        std::vector<std::string> rules;
        std::string domain;
        bool expect_blocked;
    };

    const std::vector<test_data> TEST_DATA =
        {
            { { "example1.org" }, "example1.org", true, },
            { { "example2.org", "@@example2.org" }, "example2.org", false, },
            { { "example3.org", "@@example3.org", "example3.org$important" }, "example3.org", true, },
            { { "example4.org", "@@example4.org", "example4.org$important", "@@example4.org$important" }, "example4.org", false, },
            { { "example5.org^" }, "example5.org", true, },
            { { "||example6.org|" }, "example6.org", true, },
            { { "*mple7.org" }, "example7.org", true, },
            { { "ExAmPlE8.org" }, "example8.org", true, },
            { { "example9.org" }, "EXAMPLE9.org", true, },
            { { ".example10.org" }, "sub.example10.org", true, },
            { { "http://example11.org" }, "example11.org", true, },
            { { "://example12.org" }, "example12.org", true, },
            { { "//example13.org" }, "sub.example13.org", true, },
            { { "example15.org/" }, "example15.org", true, },
            { { "example17.org:8080" }, "example17.org", true, },
            { { "example18.org|" }, "eexample18.org", true, },
            { { "example19.org^" }, "eexample19.org", true, },
            { { "|example20.org" }, "example20.orgg", true, },
            { { "example21." }, "eexample21.org", true, },
            { { "example22.org|" }, "sub.example22.org", true, },
            { { "example23.org^" }, "sub.example23.org", true, },
            { { "||example24.org" }, "sub.example24.org", true, },
            { { "||example25.org|" }, "sub.example25.org", true, },
            { { "example22.org|" }, "sub.example22.org", true, },
        };

    for (const test_data &entry : TEST_DATA) {
        for (const std::string &rule : entry.rules) {
            ASSERT_NO_FATAL_FAILURE(add_rule_in_filter(file_by_filter_name(TEST_FILTER_NAME), rule));
        }
    }

    ag::dnsfilter::engine_params params = { { { 10, file_by_filter_name(TEST_FILTER_NAME) } } };
    std::optional<ag::dnsfilter::handle> handle = filter.create(params);
    ASSERT_TRUE(handle.has_value());

    for (const test_data &entry : TEST_DATA) {
        SPDLOG_INFO("testing {}", entry.domain);
        std::vector<ag::dnsfilter::rule> rules = filter.match(handle.value(), entry.domain);
        ASSERT_GT(rules.size(), 0);
        for (const ag::dnsfilter::rule &r : rules) {
            ASSERT_EQ(r.filter_id, 10);
        }
        std::vector<const ag::dnsfilter::rule *> effective_rules = ag::dnsfilter::get_effective_rules(rules);
        ASSERT_EQ(effective_rules.size(), 1);
        if (entry.expect_blocked) {
            ASSERT_FALSE(effective_rules[0]->props.test(ag::dnsfilter::RP_EXCEPTION));
        } else {
            ASSERT_TRUE(effective_rules[0]->props.test(ag::dnsfilter::RP_EXCEPTION));
        }
    }

    filter.destroy(handle.value());
}

TEST_F(dnsfilter_test, basic_rules_no_match) {
    struct test_data {
        std::string rule;
        std::string domain;
    };

    const std::vector<test_data> TEST_DATA =
        {
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
        };

    for (const test_data &entry : TEST_DATA) {
        ASSERT_NO_FATAL_FAILURE(add_rule_in_filter(file_by_filter_name(TEST_FILTER_NAME), entry.rule));
    }

    ag::dnsfilter::engine_params params = { { { 0, file_by_filter_name(TEST_FILTER_NAME) } } };
    std::optional<ag::dnsfilter::handle> handle = filter.create(params);
    ASSERT_TRUE(handle.has_value());

    for (const test_data &entry : TEST_DATA) {
        SPDLOG_INFO("testing {}", entry.domain);
        std::vector<ag::dnsfilter::rule> rules = filter.match(handle.value(), entry.domain);
        ASSERT_EQ(rules.size(), 0);
    }

    filter.destroy(handle.value());
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
    std::optional<ag::dnsfilter::handle> handle = filter.create(params);
    ASSERT_TRUE(handle.has_value());

    for (const test_data &entry : TEST_DATA) {
        for (const std::string &d : entry.domains) {
            SPDLOG_INFO("testing {}", d);
            std::vector<ag::dnsfilter::rule> rules = filter.match(handle.value(), d);
            ASSERT_EQ(rules.size(), 1);
            ASSERT_FALSE(rules[0].props.test(ag::dnsfilter::RP_EXCEPTION));
            ASSERT_EQ(rules[0].text, entry.rule);
        }
    }

    filter.destroy(handle.value());
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
        };

    for (const test_data &entry : TEST_DATA) {
        ASSERT_NO_FATAL_FAILURE(add_rule_in_filter(file_by_filter_name(TEST_FILTER_NAME), entry.rule));
    }

    ag::dnsfilter::engine_params params = { { { 0, file_by_filter_name(TEST_FILTER_NAME) } } };
    std::optional<ag::dnsfilter::handle> handle = filter.create(params);
    ASSERT_TRUE(handle.has_value());

    for (const test_data &entry : TEST_DATA) {
        for (const std::string &d : entry.domains) {
            SPDLOG_INFO("testing {}", d);
            std::vector<ag::dnsfilter::rule> rules = filter.match(handle.value(), d);
            ASSERT_EQ(rules.size(), 1);
            ASSERT_FALSE(rules[0].props.test(ag::dnsfilter::RP_EXCEPTION));
            ASSERT_EQ(rules[0].text, entry.rule);
        }
    }

    filter.destroy(handle.value());
}

TEST_F(dnsfilter_test, hosts_file_syntax) {
    struct test_data {
        std::string rule;
        std::vector<std::string> blocked_domains;
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
        };


    for (const test_data &entry : TEST_DATA) {
        ASSERT_NO_FATAL_FAILURE(add_rule_in_filter(file_by_filter_name(TEST_FILTER_NAME), entry.rule));
    }

    ag::dnsfilter::engine_params params = { { { 0, file_by_filter_name(TEST_FILTER_NAME) } } };
    std::optional<ag::dnsfilter::handle> handle = filter.create(params);
    ASSERT_TRUE(handle.has_value());

    for (const test_data &entry : TEST_DATA) {
        for (const std::string &d : entry.blocked_domains) {
            SPDLOG_INFO("testing {}", d);
            std::vector<ag::dnsfilter::rule> rules = filter.match(handle.value(), d);
            ASSERT_EQ(rules.size(), 1);
            ASSERT_EQ(rules[0].text, entry.rule);
            ASSERT_FALSE(rules[0].props.test(ag::dnsfilter::RP_EXCEPTION));
            ASSERT_FALSE(rules[0].props.test(ag::dnsfilter::RP_IMPORTANT));
        }
    }

    filter.destroy(handle.value());
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
        };

    for (const test_data &entry : TEST_DATA) {
        for (const std::string &rule : entry.rules) {
            ASSERT_NO_FATAL_FAILURE(add_rule_in_filter(file_by_filter_name(TEST_FILTER_NAME), rule));
        }
    }

    ag::dnsfilter::engine_params params = { { { 0, file_by_filter_name(TEST_FILTER_NAME) } } };
    std::optional<ag::dnsfilter::handle> handle = filter.create(params);
    ASSERT_TRUE(handle.has_value());

    for (const test_data &entry : TEST_DATA) {
        SPDLOG_INFO("testing {}", entry.domain);
        std::vector<ag::dnsfilter::rule> rules = filter.match(handle.value(), entry.domain);
        ASSERT_EQ(rules.size(), 2);
        std::vector<const ag::dnsfilter::rule *> effective_rules = ag::dnsfilter::get_effective_rules(rules);
        ASSERT_EQ(effective_rules.size(), 0);
    }

    filter.destroy(handle.value());
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
    std::optional<ag::dnsfilter::handle> handle = filter.create(params);
    ASSERT_TRUE(handle.has_value());

    for (const test_data &entry : TEST_DATA) {
        SPDLOG_INFO("testing {}", entry.domain);
        std::vector<ag::dnsfilter::rule> rules = filter.match(handle.value(), entry.domain);
        ASSERT_GT(rules.size(), 0);
        std::vector<const ag::dnsfilter::rule *> effective_rules = ag::dnsfilter::get_effective_rules(rules);
        ASSERT_EQ(effective_rules.size(), 1);
        ASSERT_EQ(effective_rules[0]->text, entry.expected_rule);
    }

    filter.destroy(handle.value());

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
        };

    for (const test_data &entry : TEST_DATA) {
        std::vector<ag::dnsfilter::rule> rules;
        for (const std::string &text : entry.rules) {
            std::optional<rule_utils::rule> rule = rule_utils::parse(text, nullptr);
            ASSERT_TRUE(rule.has_value());
            rules.push_back(rule->public_part);
        }

        std::vector<const ag::dnsfilter::rule *> effective_rules = ag::dnsfilter::get_effective_rules(rules);
        ASSERT_EQ(effective_rules.size(), entry.expected_ids.size());
        for (size_t id : entry.expected_ids) {
            const std::string &wanted_rule = entry.rules[id];
            auto found = std::find_if(effective_rules.begin(), effective_rules.end(),
                [&wanted_rule] (const ag::dnsfilter::rule *rule) -> bool {
                    return wanted_rule == rule->text;
                });
            ASSERT_NE(found, effective_rules.end()) << wanted_rule;
            effective_rules.erase(found);
        }
        ASSERT_EQ(effective_rules.size(), 0);
    }
}
