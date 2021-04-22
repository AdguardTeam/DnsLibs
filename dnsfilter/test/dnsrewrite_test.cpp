#include <gtest/gtest.h>
#include <dnsfilter.h>
#include <rule_utils.h>
#include <algorithm>
#include <numeric>


class dnsrewrite_test : public ::testing::Test {
protected:
    ag::dnsfilter filter;
    ag::logger log = ag::create_logger("dnsfilter_test");

    void SetUp() override {
        ag::set_default_log_level(ag::TRACE);
    }

    static void check_rdf(const ldns_rdf *rdf, ldns_rdf_type type, const char *value) {
        ASSERT_EQ(ldns_rdf_get_type(rdf), type);
        auto rdf_str = ag::allocated_ptr<char>(ldns_rdf2str(rdf));
        ASSERT_STREQ(rdf_str.get(), value);
    }
};


TEST_F(dnsrewrite_test, short_keyword) {
    std::optional<rule_utils::rule> rule = rule_utils::parse("example.com$dnsrewrite=REFUSED", &log);
    ASSERT_TRUE(rule.has_value());

    auto r = ag::dnsfilter::apply_dnsrewrite_rules({ &rule->public_part });
    ASSERT_EQ(r.rules.size(), 1);
    ASSERT_TRUE(r.rewritten_info.has_value());
    ASSERT_EQ(r.rewritten_info->rcode, LDNS_RCODE_REFUSED);
    ASSERT_EQ(r.rewritten_info->rrs.size(), 0);
    ASSERT_FALSE(r.rewritten_info->cname.has_value());
}

TEST_F(dnsrewrite_test, short_a) {
    std::optional<rule_utils::rule> rule = rule_utils::parse("example.com$dnsrewrite=1.2.3.4", &log);
    ASSERT_TRUE(rule.has_value());

    auto r = ag::dnsfilter::apply_dnsrewrite_rules({ &rule->public_part });
    ASSERT_EQ(r.rules.size(), 1);
    ASSERT_TRUE(r.rewritten_info.has_value());
    ASSERT_EQ(r.rewritten_info->rcode, LDNS_RCODE_NOERROR);

    ASSERT_EQ(r.rewritten_info->rrs.size(), 1);
    ldns_rr *rr = r.rewritten_info->rrs[0].get();
    ASSERT_EQ(ldns_rr_rd_count(rr), 1);
    ASSERT_NO_FATAL_FAILURE(check_rdf(ldns_rr_rdf(rr, 0), LDNS_RDF_TYPE_A, "1.2.3.4"));

    ASSERT_FALSE(r.rewritten_info->cname.has_value());
}

TEST_F(dnsrewrite_test, short_aaaa) {
    std::optional<rule_utils::rule> rule = rule_utils::parse("example.com$dnsrewrite=a::1", &log);
    ASSERT_TRUE(rule.has_value());

    auto r = ag::dnsfilter::apply_dnsrewrite_rules({ &rule->public_part });
    ASSERT_EQ(r.rules.size(), 1);
    ASSERT_TRUE(r.rewritten_info.has_value());
    ASSERT_EQ(r.rewritten_info->rcode, LDNS_RCODE_NOERROR);

    ASSERT_EQ(r.rewritten_info->rrs.size(), 1);
    ldns_rr *rr = r.rewritten_info->rrs[0].get();
    ASSERT_EQ(ldns_rr_rd_count(rr), 1);
    ASSERT_NO_FATAL_FAILURE(check_rdf(ldns_rr_rdf(rr, 0), LDNS_RDF_TYPE_AAAA, "a::1"));

    ASSERT_FALSE(r.rewritten_info->cname.has_value());
}

TEST_F(dnsrewrite_test, short_cname) {
    std::optional<rule_utils::rule> rule = rule_utils::parse("example.com$dnsrewrite=example.org", &log);
    ASSERT_TRUE(rule.has_value());

    auto r = ag::dnsfilter::apply_dnsrewrite_rules({ &rule->public_part });
    ASSERT_EQ(r.rules.size(), 1);
    ASSERT_TRUE(r.rewritten_info.has_value());
    ASSERT_EQ(r.rewritten_info->rcode, LDNS_RCODE_NOERROR);

    ASSERT_EQ(r.rewritten_info->rrs.size(), 1);
    ldns_rr *rr = r.rewritten_info->rrs[0].get();
    ASSERT_EQ(ldns_rr_rd_count(rr), 1);
    ASSERT_NO_FATAL_FAILURE(check_rdf(ldns_rr_rdf(rr, 0), LDNS_RDF_TYPE_DNAME, "example.org."));

    ASSERT_EQ(r.rewritten_info->cname, "example.org");
}

TEST_F(dnsrewrite_test, short_cname_trailing_dot) {
    std::optional<rule_utils::rule> rule = rule_utils::parse("example.com$dnsrewrite=example.org.", &log);
    ASSERT_TRUE(rule.has_value());

    auto r = ag::dnsfilter::apply_dnsrewrite_rules({ &rule->public_part });
    ASSERT_EQ(r.rules.size(), 1);
    ASSERT_TRUE(r.rewritten_info.has_value());
    ASSERT_EQ(r.rewritten_info->rcode, LDNS_RCODE_NOERROR);

    ASSERT_EQ(r.rewritten_info->rrs.size(), 1);
    ldns_rr *rr = r.rewritten_info->rrs[0].get();
    ASSERT_EQ(ldns_rr_rd_count(rr), 1);
    ASSERT_NO_FATAL_FAILURE(check_rdf(ldns_rr_rdf(rr, 0), LDNS_RDF_TYPE_DNAME, "example.org."));

    ASSERT_EQ(r.rewritten_info->cname, "example.org.");
}

TEST_F(dnsrewrite_test, full_keyword) {
    std::optional<rule_utils::rule> rule = rule_utils::parse("example.com$dnsrewrite=SERVFAIL;;", &log);
    ASSERT_TRUE(rule.has_value());

    auto r = ag::dnsfilter::apply_dnsrewrite_rules({ &rule->public_part });
    ASSERT_EQ(r.rules.size(), 1);
    ASSERT_TRUE(r.rewritten_info.has_value());
    ASSERT_EQ(r.rewritten_info->rcode, LDNS_RCODE_SERVFAIL);
    ASSERT_EQ(r.rewritten_info->rrs.size(), 0);
    ASSERT_FALSE(r.rewritten_info->cname.has_value());
}

TEST_F(dnsrewrite_test, full_a) {
    std::optional<rule_utils::rule> rule = rule_utils::parse("example.com$dnsrewrite=NOERROR;A;1.2.3.4", &log);
    ASSERT_TRUE(rule.has_value());

    auto r = ag::dnsfilter::apply_dnsrewrite_rules({ &rule->public_part });
    ASSERT_EQ(r.rules.size(), 1);
    ASSERT_TRUE(r.rewritten_info.has_value());
    ASSERT_EQ(r.rewritten_info->rcode, LDNS_RCODE_NOERROR);

    ASSERT_EQ(r.rewritten_info->rrs.size(), 1);
    ldns_rr *rr = r.rewritten_info->rrs[0].get();
    ASSERT_EQ(ldns_rr_rd_count(rr), 1);
    ASSERT_NO_FATAL_FAILURE(check_rdf(ldns_rr_rdf(rr, 0), LDNS_RDF_TYPE_A, "1.2.3.4"));

    ASSERT_FALSE(r.rewritten_info->cname.has_value());
}

TEST_F(dnsrewrite_test, full_aaaa) {
    std::optional<rule_utils::rule> rule = rule_utils::parse("example.com$dnsrewrite=NOERROR;AAAA;abcd::1234", &log);
    ASSERT_TRUE(rule.has_value());

    auto r = ag::dnsfilter::apply_dnsrewrite_rules({ &rule->public_part });
    ASSERT_EQ(r.rules.size(), 1);
    ASSERT_TRUE(r.rewritten_info.has_value());
    ASSERT_EQ(r.rewritten_info->rcode, LDNS_RCODE_NOERROR);

    ASSERT_EQ(r.rewritten_info->rrs.size(), 1);
    ldns_rr *rr = r.rewritten_info->rrs[0].get();
    ASSERT_EQ(ldns_rr_rd_count(rr), 1);
    ASSERT_NO_FATAL_FAILURE(check_rdf(ldns_rr_rdf(rr, 0), LDNS_RDF_TYPE_AAAA, "abcd::1234"));

    ASSERT_FALSE(r.rewritten_info->cname.has_value());
}

TEST_F(dnsrewrite_test, full_ptr) {
    std::optional<rule_utils::rule> rule = rule_utils::parse("||4.3.2.1.in-addr.arpa.^$dnsrewrite=NOERROR;PTR;example.net.", &log);
    ASSERT_TRUE(rule.has_value());

    auto r = ag::dnsfilter::apply_dnsrewrite_rules({ &rule->public_part });
    ASSERT_EQ(r.rules.size(), 1);
    ASSERT_TRUE(r.rewritten_info.has_value());
    ASSERT_EQ(r.rewritten_info->rcode, LDNS_RCODE_NOERROR);

    ASSERT_EQ(r.rewritten_info->rrs.size(), 1);
    ldns_rr *rr = r.rewritten_info->rrs[0].get();
    ASSERT_EQ(ldns_rr_rd_count(rr), 1);
    ASSERT_NO_FATAL_FAILURE(check_rdf(ldns_rr_rdf(rr, 0), LDNS_RDF_TYPE_DNAME, "example.net."));

    ASSERT_FALSE(r.rewritten_info->cname.has_value());
}

TEST_F(dnsrewrite_test, full_cname) {
    std::optional<rule_utils::rule> rule = rule_utils::parse("example.com$dnsrewrite=NOERROR;CNAME;example.org", &log);
    ASSERT_TRUE(rule.has_value());

    auto r = ag::dnsfilter::apply_dnsrewrite_rules({ &rule->public_part });
    ASSERT_EQ(r.rules.size(), 1);
    ASSERT_TRUE(r.rewritten_info.has_value());
    ASSERT_EQ(r.rewritten_info->rcode, LDNS_RCODE_NOERROR);

    ASSERT_EQ(r.rewritten_info->rrs.size(), 1);
    ldns_rr *rr = r.rewritten_info->rrs[0].get();
    ASSERT_EQ(ldns_rr_rd_count(rr), 1);
    ASSERT_NO_FATAL_FAILURE(check_rdf(ldns_rr_rdf(rr, 0), LDNS_RDF_TYPE_DNAME, "example.org."));

    ASSERT_EQ(r.rewritten_info->cname, "example.org");
}

TEST_F(dnsrewrite_test, full_mx) {
    std::optional<rule_utils::rule> rule = rule_utils::parse("example.com$dnsrewrite=NOERROR;MX;42 example.mail", &log);
    ASSERT_TRUE(rule.has_value());

    auto r = ag::dnsfilter::apply_dnsrewrite_rules({ &rule->public_part });
    ASSERT_EQ(r.rules.size(), 1);
    ASSERT_TRUE(r.rewritten_info.has_value());
    ASSERT_EQ(r.rewritten_info->rcode, LDNS_RCODE_NOERROR);

    ASSERT_EQ(r.rewritten_info->rrs.size(), 1);
    ldns_rr *rr = r.rewritten_info->rrs[0].get();
    ASSERT_EQ(ldns_rr_rd_count(rr), 2);
    ASSERT_NO_FATAL_FAILURE(check_rdf(ldns_rr_rdf(rr, 0), LDNS_RDF_TYPE_INT16, "42"));
    ASSERT_NO_FATAL_FAILURE(check_rdf(ldns_rr_rdf(rr, 1), LDNS_RDF_TYPE_DNAME, "example.mail."));

    ASSERT_FALSE(r.rewritten_info->cname.has_value());
}

TEST_F(dnsrewrite_test, full_txt) {
    std::optional<rule_utils::rule> rule = rule_utils::parse("example.com$dnsrewrite=NOERROR;TXT;hello_world", &log);
    ASSERT_TRUE(rule.has_value());

    auto r = ag::dnsfilter::apply_dnsrewrite_rules({ &rule->public_part });
    ASSERT_EQ(r.rules.size(), 1);
    ASSERT_TRUE(r.rewritten_info.has_value());
    ASSERT_EQ(r.rewritten_info->rcode, LDNS_RCODE_NOERROR);

    ASSERT_EQ(r.rewritten_info->rrs.size(), 1);
    ldns_rr *rr = r.rewritten_info->rrs[0].get();
    ASSERT_EQ(ldns_rr_rd_count(rr), 1);
    ASSERT_NO_FATAL_FAILURE(check_rdf(ldns_rr_rdf(rr, 0), LDNS_RDF_TYPE_STR, "\"hello_world\""));

    ASSERT_FALSE(r.rewritten_info->cname.has_value());
}

TEST_F(dnsrewrite_test, full_https) {
    std::optional<rule_utils::rule> rule = rule_utils::parse("example.com$dnsrewrite=NOERROR;HTTPS;42 example.net alpn=h3", &log);
    ASSERT_TRUE(rule.has_value());

    auto r = ag::dnsfilter::apply_dnsrewrite_rules({ &rule->public_part });
    ASSERT_EQ(r.rules.size(), 1);
    ASSERT_TRUE(r.rewritten_info.has_value());
    ASSERT_EQ(r.rewritten_info->rcode, LDNS_RCODE_NOERROR);

    ASSERT_EQ(r.rewritten_info->rrs.size(), 1);
    ldns_rr *rr = r.rewritten_info->rrs[0].get();
    ASSERT_EQ(ldns_rr_rd_count(rr), 3);
    ASSERT_NO_FATAL_FAILURE(check_rdf(ldns_rr_rdf(rr, 0), LDNS_RDF_TYPE_INT16, "42"));
    ASSERT_NO_FATAL_FAILURE(check_rdf(ldns_rr_rdf(rr, 1), LDNS_RDF_TYPE_DNAME, "example.net."));
    ASSERT_NO_FATAL_FAILURE(check_rdf(ldns_rr_rdf(rr, 2), LDNS_RDF_TYPE_SVCPARAMS, "alpn=h3"));

    ASSERT_FALSE(r.rewritten_info->cname.has_value());
}

TEST_F(dnsrewrite_test, full_svcb) {
    std::optional<rule_utils::rule> rule = rule_utils::parse("example.com$dnsrewrite=NOERROR;SVCB;42 example.net alpn=bar port=8004", &log);
    ASSERT_TRUE(rule.has_value());

    auto r = ag::dnsfilter::apply_dnsrewrite_rules({ &rule->public_part });
    ASSERT_EQ(r.rules.size(), 1);
    ASSERT_TRUE(r.rewritten_info.has_value());
    ASSERT_EQ(r.rewritten_info->rcode, LDNS_RCODE_NOERROR);

    ASSERT_EQ(r.rewritten_info->rrs.size(), 1);
    ldns_rr *rr = r.rewritten_info->rrs[0].get();
    ASSERT_EQ(ldns_rr_rd_count(rr), 3);
    ASSERT_NO_FATAL_FAILURE(check_rdf(ldns_rr_rdf(rr, 0), LDNS_RDF_TYPE_INT16, "42"));
    ASSERT_NO_FATAL_FAILURE(check_rdf(ldns_rr_rdf(rr, 1), LDNS_RDF_TYPE_DNAME, "example.net."));
    ASSERT_NO_FATAL_FAILURE(check_rdf(ldns_rr_rdf(rr, 2), LDNS_RDF_TYPE_SVCPARAMS, "alpn=bar port=8004"));

    ASSERT_FALSE(r.rewritten_info->cname.has_value());
}

TEST_F(dnsrewrite_test, a_vs_aaaa_query) {
    ag::dnsfilter::engine_params params = { { { 10, "example.com$dnsrewrite=NOERROR;A;1.2.3.4", true } } };
    auto [handle, err_or_warn] = filter.create(params);
    ASSERT_TRUE(handle) << *err_or_warn;

    std::vector<ag::dnsfilter::rule> rules = filter.match(handle, { "example.com", LDNS_RR_TYPE_AAAA });
    ASSERT_EQ(rules.size(), 0);

    filter.destroy(handle);
}

TEST_F(dnsrewrite_test, aaaa_vs_a_query) {
    ag::dnsfilter::engine_params params = { { { 10, "example.com$dnsrewrite=NOERROR;AAAA;abcd::1234", true } } };
    auto [handle, err_or_warn] = filter.create(params);
    ASSERT_TRUE(handle) << *err_or_warn;

    std::vector<ag::dnsfilter::rule> rules = filter.match(handle, { "example.com", LDNS_RR_TYPE_A });
    ASSERT_EQ(rules.size(), 0);

    filter.destroy(handle);
}

TEST_F(dnsrewrite_test, match_reverse) {
    ag::dnsfilter::engine_params params = { { { 10, "||4.3.2.1.in-addr.arpa.^$dnsrewrite=REFUSED;PTR;example.com.", true } } };
    auto [handle, err_or_warn] = filter.create(params);
    ASSERT_TRUE(handle) << *err_or_warn;

    std::vector<ag::dnsfilter::rule> rules = filter.match(handle, { "4.3.2.1.in-addr.arpa", LDNS_RR_TYPE_PTR });
    ASSERT_EQ(rules.size(), 1);
    rules = filter.match(handle, { "4.3.2.1.in-addr.arpa", LDNS_RR_TYPE_A });
    ASSERT_EQ(rules.size(), 0);

    filter.destroy(handle);
}

TEST_F(dnsrewrite_test, match_reverse_ipv6) {
    ag::dnsfilter::engine_params params = { { { 10,
            "||a.9.8.7.6.5.e.f.f.f.4.3.2.1.0.0.0.0.0.0.0.0.f.0.8.b.d.0.1.0.0.2.ip6.arpa.^$dnsrewrite=REFUSED;PTR;example.com.", true } } };
    auto [handle, err_or_warn] = filter.create(params);
    ASSERT_TRUE(handle) << *err_or_warn;

    std::vector<ag::dnsfilter::rule> rules = filter.match(handle,
            { "a.9.8.7.6.5.e.f.f.f.4.3.2.1.0.0.0.0.0.0.0.0.f.0.8.b.d.0.1.0.0.2.ip6.arpa", LDNS_RR_TYPE_PTR });
    ASSERT_EQ(rules.size(), 1);
    rules = filter.match(handle,
            { "a.9.8.7.6.5.e.f.f.f.4.3.2.1.0.0.0.0.0.0.0.0.f.0.8.b.d.0.1.0.0.2.ip6.arpa", LDNS_RR_TYPE_A });
    ASSERT_EQ(rules.size(), 0);

    filter.destroy(handle);
}

TEST_F(dnsrewrite_test, cname_match) {
    ag::dnsfilter::engine_params params = { { { 10, "example.com$dnsrewrite=NOERROR;CNAME;example.net.", true } } };
    auto [handle, err_or_warn] = filter.create(params);
    ASSERT_TRUE(handle) << *err_or_warn;

    std::vector<ag::dnsfilter::rule> rules = filter.match(handle, { "example.com", LDNS_RR_TYPE_A });
    ASSERT_EQ(rules.size(), 1);
    rules = filter.match(handle, { "example.com", LDNS_RR_TYPE_AAAA });
    ASSERT_EQ(rules.size(), 1);
    rules = filter.match(handle, { "example.com", LDNS_RR_TYPE_PTR });
    ASSERT_EQ(rules.size(), 0);

    filter.destroy(handle);
}

TEST_F(dnsrewrite_test, multiple_noerror) {
    struct test_data {
        struct rdf_data {
            ldns_rdf_type type;
            std::string value;
        };

        std::string rule_text;
        std::vector<rdf_data> rdfs;
    };

    const test_data TEST_DATA[] = {
            { "example.com$dnsrewrite=NOERROR;A;1.2.3.4",
                    { { LDNS_RDF_TYPE_A, "1.2.3.4" } } },
            { "example.com$dnsrewrite=NOERROR;AAAA;abcd::1234",
                    { { LDNS_RDF_TYPE_AAAA, "abcd::1234" } } },
            { "example.com$dnsrewrite=NOERROR;TXT;hello_world",
                    { { LDNS_RDF_TYPE_STR, "\"hello_world\"" } } },
            { "example.com$dnsrewrite=NOERROR;MX;42 example.mail",
                    { { LDNS_RDF_TYPE_INT16, "42" }, { LDNS_RDF_TYPE_DNAME, "example.mail." } } },
    };

    std::vector<rule_utils::rule> rules;
    for (const test_data &d : TEST_DATA) {
    std::optional<rule_utils::rule> rule = rule_utils::parse(d.rule_text, &log);
    ASSERT_TRUE(rule.has_value());
    rules.emplace_back(std::move(rule.value()));
    }

    auto rules_to_apply = std::accumulate(rules.begin(), rules.end(),
            std::vector<const ag::dnsfilter::rule *>{},
            [] (auto acc, const rule_utils::rule &r) {
                acc.emplace_back(&r.public_part);
                return acc;
            });
    auto r = ag::dnsfilter::apply_dnsrewrite_rules(rules_to_apply);
    ASSERT_EQ(r.rules.size(), std::size(TEST_DATA));
    ASSERT_TRUE(r.rewritten_info.has_value());
    ASSERT_EQ(r.rewritten_info->rcode, LDNS_RCODE_NOERROR);

    ASSERT_EQ(r.rewritten_info->rrs.size(), std::size(TEST_DATA));
    for (size_t i = 0; i < std::size(TEST_DATA); ++i) {
        const test_data &d = TEST_DATA[i];
        ldns_rr *rr = r.rewritten_info->rrs[i].get();
        ASSERT_EQ(ldns_rr_rd_count(rr), d.rdfs.size()) << d.rule_text;
        for (size_t j = 0; j < d.rdfs.size(); ++j) {
            const auto &rdf = d.rdfs[j];
            ASSERT_NO_FATAL_FAILURE(check_rdf(ldns_rr_rdf(rr, j), rdf.type, rdf.value.c_str())) << d.rule_text;
        }
    }

    ASSERT_FALSE(r.rewritten_info->cname.has_value());
}

TEST_F(dnsrewrite_test, multiple_refused_precedence) {
    const std::string RULES[] = {
            "example.com$dnsrewrite=NOERROR;A;1.2.3.4",
            "example.com$dnsrewrite=NOERROR;AAAA;abcd::1234",
            "example.com$dnsrewrite=NOERROR;TXT;hello_world",
            "example.com$dnsrewrite=NOERROR;MX;42 example.mail",
            "example.com$dnsrewrite=REFUSED",
    };

    std::vector<rule_utils::rule> rules;
    for (const std::string &r : RULES) {
        std::optional<rule_utils::rule> rule = rule_utils::parse(r, &log);
        ASSERT_TRUE(rule.has_value());
        rules.emplace_back(std::move(rule.value()));
    }

    auto rules_to_apply = std::accumulate(rules.begin(), rules.end(),
            std::vector<const ag::dnsfilter::rule *>{},
            [] (auto acc, const rule_utils::rule &r) {
                acc.emplace_back(&r.public_part);
                return acc;
            });

    auto r = ag::dnsfilter::apply_dnsrewrite_rules(rules_to_apply);
    ASSERT_EQ(r.rules.size(), 1);
    ASSERT_TRUE(r.rewritten_info.has_value());
    ASSERT_EQ(r.rewritten_info->rcode, LDNS_RCODE_REFUSED);
}

TEST_F(dnsrewrite_test, multiple_cname_precedence) {
    const std::string RULES[] = {
            "example.com$dnsrewrite=NOERROR;A;1.2.3.4",
            "example.com$dnsrewrite=NOERROR;AAAA;abcd::1234",
            "example.com$dnsrewrite=NOERROR;TXT;hello_world",
            "example.com$dnsrewrite=NOERROR;MX;42 example.mail",
            "example.com$dnsrewrite=example.net",
    };

    std::vector<rule_utils::rule> rules;
    for (const std::string &r : RULES) {
        std::optional<rule_utils::rule> rule = rule_utils::parse(r, &log);
        ASSERT_TRUE(rule.has_value());
        rules.emplace_back(std::move(rule.value()));
    }

    auto rules_to_apply = std::accumulate(rules.begin(), rules.end(),
            std::vector<const ag::dnsfilter::rule *>{},
            [] (auto acc, const rule_utils::rule &r) {
                acc.emplace_back(&r.public_part);
                return acc;
            });

    auto r = ag::dnsfilter::apply_dnsrewrite_rules(rules_to_apply);
    ASSERT_EQ(r.rules.size(), 1);
    ASSERT_TRUE(r.rewritten_info.has_value());
    ASSERT_EQ(r.rewritten_info->rcode, LDNS_RCODE_NOERROR);
    ASSERT_EQ(r.rewritten_info->cname, "example.net");
}

TEST_F(dnsrewrite_test, exclude_all) {
    const std::string RULES[] = {
            "example.com$dnsrewrite=NOERROR;TXT;hello_world",
            "example.com$dnsrewrite=REFUSED",
            "@@example.com$dnsrewrite",
    };

    std::vector<rule_utils::rule> rules;
    for (const std::string &r : RULES) {
        std::optional<rule_utils::rule> rule = rule_utils::parse(r, &log);
        ASSERT_TRUE(rule.has_value());
        rules.emplace_back(std::move(rule.value()));
    }

    auto rules_to_apply = std::accumulate(rules.begin(), rules.end(),
            std::vector<const ag::dnsfilter::rule *>{},
            [] (auto acc, const rule_utils::rule &r) {
                acc.emplace_back(&r.public_part);
                return acc;
            });

    auto r = ag::dnsfilter::apply_dnsrewrite_rules(rules_to_apply);
    ASSERT_EQ(r.rules.size(), 1);
    ASSERT_TRUE(std::get<ag::dnsfilter::adblock_rule_info>(r.rules[0]->content)
            .props.test(ag::dnsfilter::DARP_EXCEPTION));
    ASSERT_FALSE(r.rewritten_info.has_value());
}

TEST_F(dnsrewrite_test, exclude_specific) {
    const std::string RULES[] = {
            "example.com$dnsrewrite=NOERROR;TXT;hello_world",
            "example.com$dnsrewrite=1.2.3.4",
            "@@example.com$dnsrewrite=1.2.3.4",
    };

    std::vector<rule_utils::rule> rules;
    for (const std::string &r : RULES) {
        std::optional<rule_utils::rule> rule = rule_utils::parse(r, &log);
        ASSERT_TRUE(rule.has_value());
        rules.emplace_back(std::move(rule.value()));
    }

    auto rules_to_apply = std::accumulate(rules.begin(), rules.end(),
            std::vector<const ag::dnsfilter::rule *>{},
            [] (auto acc, const rule_utils::rule &r) {
                acc.emplace_back(&r.public_part);
                return acc;
            });

    auto r = ag::dnsfilter::apply_dnsrewrite_rules(rules_to_apply);
    ASSERT_EQ(r.rules.size(), 2);
    ASSERT_TRUE(std::any_of(r.rules.begin(), r.rules.end(),
            [] (const ag::dnsfilter::rule *r) {
                return std::get<ag::dnsfilter::adblock_rule_info>(r->content)
                        .props.test(ag::dnsfilter::DARP_EXCEPTION);
            }));
    ASSERT_TRUE(std::any_of(r.rules.begin(), r.rules.end(),
            [] (const ag::dnsfilter::rule *r) {
                return !std::get<ag::dnsfilter::adblock_rule_info>(r->content)
                        .props.test(ag::dnsfilter::DARP_EXCEPTION);
            }));
    ASSERT_TRUE(r.rewritten_info.has_value());
}
