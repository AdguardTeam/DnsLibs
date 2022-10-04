#include <algorithm>
#include <gtest/gtest.h>
#include <numeric>

#include "dns/dnsfilter/dnsfilter.h"

#include "../rule_utils.h"

namespace ag::dns::dnsfilter::test {

class DnsrewriteTest : public ::testing::Test {
protected:
    DnsFilter filter;
    Logger log{"dnsfilter_test"};

    void SetUp() override {
        Logger::set_log_level(ag::LogLevel::LOG_LEVEL_TRACE);
    }

    static void check_rdf(const ldns_rdf *rdf, ldns_rdf_type type, const char *value) {
        ASSERT_EQ(ldns_rdf_get_type(rdf), type);
        auto rdf_str = ag::AllocatedPtr<char>(ldns_rdf2str(rdf));
        ASSERT_STREQ(rdf_str.get(), value);
    }
};

TEST_F(DnsrewriteTest, ShortKeyword) {
    std::optional<rule_utils::Rule> rule = rule_utils::parse("example.com$dnsrewrite=REFUSED", &log);
    ASSERT_TRUE(rule.has_value());

    auto r = DnsFilter::apply_dnsrewrite_rules({&rule->public_part});
    ASSERT_EQ(r.rules.size(), 1);
    ASSERT_TRUE(r.rewritten_info.has_value());
    ASSERT_EQ(r.rewritten_info->rcode, LDNS_RCODE_REFUSED);
    ASSERT_EQ(r.rewritten_info->rrs.size(), 0);
    ASSERT_FALSE(r.rewritten_info->cname.has_value());
}

TEST_F(DnsrewriteTest, ShortA) {
    std::optional<rule_utils::Rule> rule = rule_utils::parse("example.com$dnsrewrite=1.2.3.4", &log);
    ASSERT_TRUE(rule.has_value());

    auto r = DnsFilter::apply_dnsrewrite_rules({&rule->public_part});
    ASSERT_EQ(r.rules.size(), 1);
    ASSERT_TRUE(r.rewritten_info.has_value());
    ASSERT_EQ(r.rewritten_info->rcode, LDNS_RCODE_NOERROR);

    ASSERT_EQ(r.rewritten_info->rrs.size(), 1);
    ldns_rr *rr = r.rewritten_info->rrs[0].get();
    ASSERT_EQ(ldns_rr_rd_count(rr), 1);
    ASSERT_NO_FATAL_FAILURE(check_rdf(ldns_rr_rdf(rr, 0), LDNS_RDF_TYPE_A, "1.2.3.4"));

    ASSERT_FALSE(r.rewritten_info->cname.has_value());
}

TEST_F(DnsrewriteTest, ShortAAAA) {
    std::optional<rule_utils::Rule> rule = rule_utils::parse("example.com$dnsrewrite=a::1", &log);
    ASSERT_TRUE(rule.has_value());

    auto r = DnsFilter::apply_dnsrewrite_rules({&rule->public_part});
    ASSERT_EQ(r.rules.size(), 1);
    ASSERT_TRUE(r.rewritten_info.has_value());
    ASSERT_EQ(r.rewritten_info->rcode, LDNS_RCODE_NOERROR);

    ASSERT_EQ(r.rewritten_info->rrs.size(), 1);
    ldns_rr *rr = r.rewritten_info->rrs[0].get();
    ASSERT_EQ(ldns_rr_rd_count(rr), 1);
    ASSERT_NO_FATAL_FAILURE(check_rdf(ldns_rr_rdf(rr, 0), LDNS_RDF_TYPE_AAAA, "a::1"));

    ASSERT_FALSE(r.rewritten_info->cname.has_value());
}

TEST_F(DnsrewriteTest, ShortCname) {
    std::optional<rule_utils::Rule> rule = rule_utils::parse("example.com$dnsrewrite=example.org", &log);
    ASSERT_TRUE(rule.has_value());

    auto r = DnsFilter::apply_dnsrewrite_rules({&rule->public_part});
    ASSERT_EQ(r.rules.size(), 1);
    ASSERT_TRUE(r.rewritten_info.has_value());
    ASSERT_EQ(r.rewritten_info->rcode, LDNS_RCODE_NOERROR);

    ASSERT_EQ(r.rewritten_info->rrs.size(), 1);
    ldns_rr *rr = r.rewritten_info->rrs[0].get();
    ASSERT_EQ(ldns_rr_rd_count(rr), 1);
    ASSERT_NO_FATAL_FAILURE(check_rdf(ldns_rr_rdf(rr, 0), LDNS_RDF_TYPE_DNAME, "example.org."));

    ASSERT_EQ(r.rewritten_info->cname, "example.org");
}

TEST_F(DnsrewriteTest, ShortCnameTrailingDot) {
    std::optional<rule_utils::Rule> rule = rule_utils::parse("example.com$dnsrewrite=example.org.", &log);
    ASSERT_TRUE(rule.has_value());

    auto r = DnsFilter::apply_dnsrewrite_rules({&rule->public_part});
    ASSERT_EQ(r.rules.size(), 1);
    ASSERT_TRUE(r.rewritten_info.has_value());
    ASSERT_EQ(r.rewritten_info->rcode, LDNS_RCODE_NOERROR);

    ASSERT_EQ(r.rewritten_info->rrs.size(), 1);
    ldns_rr *rr = r.rewritten_info->rrs[0].get();
    ASSERT_EQ(ldns_rr_rd_count(rr), 1);
    ASSERT_NO_FATAL_FAILURE(check_rdf(ldns_rr_rdf(rr, 0), LDNS_RDF_TYPE_DNAME, "example.org."));

    ASSERT_EQ(r.rewritten_info->cname, "example.org.");
}

TEST_F(DnsrewriteTest, FullKeyword) {
    std::optional<rule_utils::Rule> rule = rule_utils::parse("example.com$dnsrewrite=SERVFAIL;;", &log);
    ASSERT_TRUE(rule.has_value());

    auto r = DnsFilter::apply_dnsrewrite_rules({&rule->public_part});
    ASSERT_EQ(r.rules.size(), 1);
    ASSERT_TRUE(r.rewritten_info.has_value());
    ASSERT_EQ(r.rewritten_info->rcode, LDNS_RCODE_SERVFAIL);
    ASSERT_EQ(r.rewritten_info->rrs.size(), 0);
    ASSERT_FALSE(r.rewritten_info->cname.has_value());
}

TEST_F(DnsrewriteTest, FullA) {
    std::optional<rule_utils::Rule> rule = rule_utils::parse("example.com$dnsrewrite=NOERROR;A;1.2.3.4", &log);
    ASSERT_TRUE(rule.has_value());

    auto r = DnsFilter::apply_dnsrewrite_rules({&rule->public_part});
    ASSERT_EQ(r.rules.size(), 1);
    ASSERT_TRUE(r.rewritten_info.has_value());
    ASSERT_EQ(r.rewritten_info->rcode, LDNS_RCODE_NOERROR);

    ASSERT_EQ(r.rewritten_info->rrs.size(), 1);
    ldns_rr *rr = r.rewritten_info->rrs[0].get();
    ASSERT_EQ(ldns_rr_rd_count(rr), 1);
    ASSERT_NO_FATAL_FAILURE(check_rdf(ldns_rr_rdf(rr, 0), LDNS_RDF_TYPE_A, "1.2.3.4"));

    ASSERT_FALSE(r.rewritten_info->cname.has_value());
}

TEST_F(DnsrewriteTest, FullAAAA) {
    std::optional<rule_utils::Rule> rule = rule_utils::parse("example.com$dnsrewrite=NOERROR;AAAA;abcd::1234", &log);
    ASSERT_TRUE(rule.has_value());

    auto r = DnsFilter::apply_dnsrewrite_rules({&rule->public_part});
    ASSERT_EQ(r.rules.size(), 1);
    ASSERT_TRUE(r.rewritten_info.has_value());
    ASSERT_EQ(r.rewritten_info->rcode, LDNS_RCODE_NOERROR);

    ASSERT_EQ(r.rewritten_info->rrs.size(), 1);
    ldns_rr *rr = r.rewritten_info->rrs[0].get();
    ASSERT_EQ(ldns_rr_rd_count(rr), 1);
    ASSERT_NO_FATAL_FAILURE(check_rdf(ldns_rr_rdf(rr, 0), LDNS_RDF_TYPE_AAAA, "abcd::1234"));

    ASSERT_FALSE(r.rewritten_info->cname.has_value());
}

TEST_F(DnsrewriteTest, FullPTR) {
    std::optional<rule_utils::Rule> rule
            = rule_utils::parse("||4.3.2.1.in-addr.arpa.^$dnsrewrite=NOERROR;PTR;example.net.", &log);
    ASSERT_TRUE(rule.has_value());

    auto r = DnsFilter::apply_dnsrewrite_rules({&rule->public_part});
    ASSERT_EQ(r.rules.size(), 1);
    ASSERT_TRUE(r.rewritten_info.has_value());
    ASSERT_EQ(r.rewritten_info->rcode, LDNS_RCODE_NOERROR);

    ASSERT_EQ(r.rewritten_info->rrs.size(), 1);
    ldns_rr *rr = r.rewritten_info->rrs[0].get();
    ASSERT_EQ(ldns_rr_rd_count(rr), 1);
    ASSERT_NO_FATAL_FAILURE(check_rdf(ldns_rr_rdf(rr, 0), LDNS_RDF_TYPE_DNAME, "example.net."));

    ASSERT_FALSE(r.rewritten_info->cname.has_value());
}

TEST_F(DnsrewriteTest, FullCname) {
    std::optional<rule_utils::Rule> rule = rule_utils::parse("example.com$dnsrewrite=NOERROR;CNAME;example.org", &log);
    ASSERT_TRUE(rule.has_value());

    auto r = DnsFilter::apply_dnsrewrite_rules({&rule->public_part});
    ASSERT_EQ(r.rules.size(), 1);
    ASSERT_TRUE(r.rewritten_info.has_value());
    ASSERT_EQ(r.rewritten_info->rcode, LDNS_RCODE_NOERROR);

    ASSERT_EQ(r.rewritten_info->rrs.size(), 1);
    ldns_rr *rr = r.rewritten_info->rrs[0].get();
    ASSERT_EQ(ldns_rr_rd_count(rr), 1);
    ASSERT_NO_FATAL_FAILURE(check_rdf(ldns_rr_rdf(rr, 0), LDNS_RDF_TYPE_DNAME, "example.org."));

    ASSERT_EQ(r.rewritten_info->cname, "example.org");
}

TEST_F(DnsrewriteTest, FullMX) {
    std::optional<rule_utils::Rule> rule = rule_utils::parse("example.com$dnsrewrite=NOERROR;MX;42 example.mail", &log);
    ASSERT_TRUE(rule.has_value());

    auto r = DnsFilter::apply_dnsrewrite_rules({&rule->public_part});
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

TEST_F(DnsrewriteTest, FullTXT) {
    std::optional<rule_utils::Rule> rule = rule_utils::parse("example.com$dnsrewrite=NOERROR;TXT;hello_world", &log);
    ASSERT_TRUE(rule.has_value());

    auto r = DnsFilter::apply_dnsrewrite_rules({&rule->public_part});
    ASSERT_EQ(r.rules.size(), 1);
    ASSERT_TRUE(r.rewritten_info.has_value());
    ASSERT_EQ(r.rewritten_info->rcode, LDNS_RCODE_NOERROR);

    ASSERT_EQ(r.rewritten_info->rrs.size(), 1);
    ldns_rr *rr = r.rewritten_info->rrs[0].get();
    ASSERT_EQ(ldns_rr_rd_count(rr), 1);
    ASSERT_NO_FATAL_FAILURE(check_rdf(ldns_rr_rdf(rr, 0), LDNS_RDF_TYPE_STR, "\"hello_world\""));

    ASSERT_FALSE(r.rewritten_info->cname.has_value());
}

TEST_F(DnsrewriteTest, FullHTTPS) {
    std::optional<rule_utils::Rule> rule
            = rule_utils::parse("example.com$dnsrewrite=NOERROR;HTTPS;42 example.net alpn=h3", &log);
    ASSERT_TRUE(rule.has_value());

    auto r = DnsFilter::apply_dnsrewrite_rules({&rule->public_part});
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

TEST_F(DnsrewriteTest, FullSVCB) {
    std::optional<rule_utils::Rule> rule
            = rule_utils::parse("example.com$dnsrewrite=NOERROR;SVCB;42 example.net alpn=bar port=8004", &log);
    ASSERT_TRUE(rule.has_value());

    auto r = DnsFilter::apply_dnsrewrite_rules({&rule->public_part});
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

TEST_F(DnsrewriteTest, A_vs_AAAA_query) {
    DnsFilter::EngineParams params = {{{10, "example.com$dnsrewrite=NOERROR;A;1.2.3.4", true}}};
    auto [handle, err_or_warn] = filter.create(params);
    ASSERT_TRUE(handle) << err_or_warn->str();

    std::vector<DnsFilter::Rule> rules = filter.match(handle, {"example.com", LDNS_RR_TYPE_AAAA});
    ASSERT_EQ(rules.size(), 0);

    filter.destroy(handle);
}

TEST_F(DnsrewriteTest, AAAA_vs_A_query) {
    DnsFilter::EngineParams params = {{{10, "example.com$dnsrewrite=NOERROR;AAAA;abcd::1234", true}}};
    auto [handle, err_or_warn] = filter.create(params);
    ASSERT_TRUE(handle) << err_or_warn->str();

    std::vector<DnsFilter::Rule> rules = filter.match(handle, {"example.com", LDNS_RR_TYPE_A});
    ASSERT_EQ(rules.size(), 0);

    filter.destroy(handle);
}

TEST_F(DnsrewriteTest, MatchReverse) {
    DnsFilter::EngineParams params = {{{10, "||4.3.2.1.in-addr.arpa.^$dnsrewrite=REFUSED;PTR;example.com.", true}}};
    auto [handle, err_or_warn] = filter.create(params);
    ASSERT_TRUE(handle) << err_or_warn->str();

    std::vector<DnsFilter::Rule> rules = filter.match(handle, {"4.3.2.1.in-addr.arpa", LDNS_RR_TYPE_PTR});
    ASSERT_EQ(rules.size(), 1);
    rules = filter.match(handle, {"4.3.2.1.in-addr.arpa", LDNS_RR_TYPE_A});
    ASSERT_EQ(rules.size(), 0);

    filter.destroy(handle);
}

TEST_F(DnsrewriteTest, MatchReverseIpv6) {
    DnsFilter::EngineParams params = {{{10,
            "||a.9.8.7.6.5.e.f.f.f.4.3.2.1.0.0.0.0.0.0.0.0.f.0.8.b.d.0.1.0.0.2.ip6.arpa.^$dnsrewrite=REFUSED;PTR;"
            "example.com.",
            true}}};
    auto [handle, err_or_warn] = filter.create(params);
    ASSERT_TRUE(handle) << err_or_warn->str();

    std::vector<DnsFilter::Rule> rules = filter.match(
            handle, {"a.9.8.7.6.5.e.f.f.f.4.3.2.1.0.0.0.0.0.0.0.0.f.0.8.b.d.0.1.0.0.2.ip6.arpa", LDNS_RR_TYPE_PTR});
    ASSERT_EQ(rules.size(), 1);
    rules = filter.match(
            handle, {"a.9.8.7.6.5.e.f.f.f.4.3.2.1.0.0.0.0.0.0.0.0.f.0.8.b.d.0.1.0.0.2.ip6.arpa", LDNS_RR_TYPE_A});
    ASSERT_EQ(rules.size(), 0);

    filter.destroy(handle);
}

TEST_F(DnsrewriteTest, CnameMatch) {
    DnsFilter::EngineParams params = {{{10, "example.com$dnsrewrite=NOERROR;CNAME;example.net.", true}}};
    auto [handle, err_or_warn] = filter.create(params);
    ASSERT_TRUE(handle) << err_or_warn->str();

    std::vector<DnsFilter::Rule> rules = filter.match(handle, {"example.com", LDNS_RR_TYPE_A});
    ASSERT_EQ(rules.size(), 1);
    rules = filter.match(handle, {"example.com", LDNS_RR_TYPE_AAAA});
    ASSERT_EQ(rules.size(), 1);
    rules = filter.match(handle, {"example.com", LDNS_RR_TYPE_PTR});
    ASSERT_EQ(rules.size(), 0);

    filter.destroy(handle);
}

TEST_F(DnsrewriteTest, Multiple_Noerror) {
    struct TestData {
        struct RdfData {
            ldns_rdf_type type;
            std::string value;
        };

        std::string rule_text;
        std::vector<RdfData> rdfs;
    };

    const TestData TEST_DATA[] = {
            {"example.com$dnsrewrite=NOERROR;A;1.2.3.4", {{LDNS_RDF_TYPE_A, "1.2.3.4"}}},
            {"example.com$dnsrewrite=NOERROR;AAAA;abcd::1234", {{LDNS_RDF_TYPE_AAAA, "abcd::1234"}}},
            {"example.com$dnsrewrite=NOERROR;TXT;hello_world", {{LDNS_RDF_TYPE_STR, "\"hello_world\""}}},
            {"example.com$dnsrewrite=NOERROR;MX;42 example.mail",
                    {{LDNS_RDF_TYPE_INT16, "42"}, {LDNS_RDF_TYPE_DNAME, "example.mail."}}},
    };

    std::vector<rule_utils::Rule> rules;
    for (const TestData &d : TEST_DATA) {
        std::optional<rule_utils::Rule> rule = rule_utils::parse(d.rule_text, &log);
        ASSERT_TRUE(rule.has_value());
        rules.emplace_back(std::move(rule.value()));
    }

    auto rules_to_apply = std::accumulate(rules.begin(), rules.end(), std::vector<const DnsFilter::Rule *>{},
            [](auto acc, const rule_utils::Rule &r) {
                acc.emplace_back(&r.public_part);
                return acc;
            });
    auto r = DnsFilter::apply_dnsrewrite_rules(rules_to_apply);
    ASSERT_EQ(r.rules.size(), std::size(TEST_DATA));
    ASSERT_TRUE(r.rewritten_info.has_value());
    ASSERT_EQ(r.rewritten_info->rcode, LDNS_RCODE_NOERROR);

    ASSERT_EQ(r.rewritten_info->rrs.size(), std::size(TEST_DATA));
    for (size_t i = 0; i < std::size(TEST_DATA); ++i) {
        const TestData &d = TEST_DATA[i];
        ldns_rr *rr = r.rewritten_info->rrs[i].get();
        ASSERT_EQ(ldns_rr_rd_count(rr), d.rdfs.size()) << d.rule_text;
        for (size_t j = 0; j < d.rdfs.size(); ++j) {
            const auto &rdf = d.rdfs[j];
            ASSERT_NO_FATAL_FAILURE(check_rdf(ldns_rr_rdf(rr, j), rdf.type, rdf.value.c_str())) << d.rule_text;
        }
    }

    ASSERT_FALSE(r.rewritten_info->cname.has_value());
}

TEST_F(DnsrewriteTest, MultipleRefusedPrecedence) {
    const std::string RULES[] = {
            "example.com$dnsrewrite=NOERROR;A;1.2.3.4",
            "example.com$dnsrewrite=NOERROR;AAAA;abcd::1234",
            "example.com$dnsrewrite=NOERROR;TXT;hello_world",
            "example.com$dnsrewrite=NOERROR;MX;42 example.mail",
            "example.com$dnsrewrite=REFUSED",
    };

    std::vector<rule_utils::Rule> rules;
    for (const std::string &r : RULES) {
        std::optional<rule_utils::Rule> rule = rule_utils::parse(r, &log);
        ASSERT_TRUE(rule.has_value());
        rules.emplace_back(std::move(rule.value()));
    }

    auto rules_to_apply = std::accumulate(rules.begin(), rules.end(), std::vector<const DnsFilter::Rule *>{},
            [](auto acc, const rule_utils::Rule &r) {
                acc.emplace_back(&r.public_part);
                return acc;
            });

    auto r = DnsFilter::apply_dnsrewrite_rules(rules_to_apply);
    ASSERT_EQ(r.rules.size(), 1);
    ASSERT_TRUE(r.rewritten_info.has_value());
    ASSERT_EQ(r.rewritten_info->rcode, LDNS_RCODE_REFUSED);
}

TEST_F(DnsrewriteTest, MultipleCnamePrecedence) {
    const std::string RULES[] = {
            "example.com$dnsrewrite=NOERROR;A;1.2.3.4",
            "example.com$dnsrewrite=NOERROR;AAAA;abcd::1234",
            "example.com$dnsrewrite=NOERROR;TXT;hello_world",
            "example.com$dnsrewrite=NOERROR;MX;42 example.mail",
            "example.com$dnsrewrite=example.net",
    };

    std::vector<rule_utils::Rule> rules;
    for (const std::string &r : RULES) {
        std::optional<rule_utils::Rule> rule = rule_utils::parse(r, &log);
        ASSERT_TRUE(rule.has_value());
        rules.emplace_back(std::move(rule.value()));
    }

    auto rules_to_apply = std::accumulate(rules.begin(), rules.end(), std::vector<const DnsFilter::Rule *>{},
            [](auto acc, const rule_utils::Rule &r) {
                acc.emplace_back(&r.public_part);
                return acc;
            });

    auto r = DnsFilter::apply_dnsrewrite_rules(rules_to_apply);
    ASSERT_EQ(r.rules.size(), 1);
    ASSERT_TRUE(r.rewritten_info.has_value());
    ASSERT_EQ(r.rewritten_info->rcode, LDNS_RCODE_NOERROR);
    ASSERT_EQ(r.rewritten_info->cname, "example.net");
}

TEST_F(DnsrewriteTest, ExcludeAll) {
    const std::string RULES[] = {
            "example.com$dnsrewrite=NOERROR;TXT;hello_world",
            "example.com$dnsrewrite=REFUSED",
            "@@example.com$dnsrewrite",
    };

    std::vector<rule_utils::Rule> rules;
    for (const std::string &r : RULES) {
        std::optional<rule_utils::Rule> rule = rule_utils::parse(r, &log);
        ASSERT_TRUE(rule.has_value());
        rules.emplace_back(std::move(rule.value()));
    }

    auto rules_to_apply = std::accumulate(rules.begin(), rules.end(), std::vector<const DnsFilter::Rule *>{},
            [](auto acc, const rule_utils::Rule &r) {
                acc.emplace_back(&r.public_part);
                return acc;
            });

    auto r = DnsFilter::apply_dnsrewrite_rules(rules_to_apply);
    ASSERT_EQ(r.rules.size(), 1);
    ASSERT_TRUE(std::get<DnsFilter::AdblockRuleInfo>(r.rules[0]->content).props.test(DnsFilter::DARP_EXCEPTION));
    ASSERT_FALSE(r.rewritten_info.has_value());
}

TEST_F(DnsrewriteTest, ExcludeSpecific) {
    const std::string RULES[] = {
            "example.com$dnsrewrite=NOERROR;TXT;hello_world",
            "example.com$dnsrewrite=1.2.3.4",
            "@@example.com$dnsrewrite=1.2.3.4",
    };

    std::vector<rule_utils::Rule> rules;
    for (const std::string &r : RULES) {
        std::optional<rule_utils::Rule> rule = rule_utils::parse(r, &log);
        ASSERT_TRUE(rule.has_value());
        rules.emplace_back(std::move(rule.value()));
    }

    auto rules_to_apply = std::accumulate(rules.begin(), rules.end(), std::vector<const DnsFilter::Rule *>{},
            [](auto acc, const rule_utils::Rule &r) {
                acc.emplace_back(&r.public_part);
                return acc;
            });

    auto r = DnsFilter::apply_dnsrewrite_rules(rules_to_apply);
    ASSERT_EQ(r.rules.size(), 2);
    ASSERT_TRUE(std::any_of(r.rules.begin(), r.rules.end(), [](const DnsFilter::Rule *r) {
        return std::get<DnsFilter::AdblockRuleInfo>(r->content).props.test(DnsFilter::DARP_EXCEPTION);
    }));
    ASSERT_TRUE(std::any_of(r.rules.begin(), r.rules.end(), [](const DnsFilter::Rule *r) {
        return !std::get<DnsFilter::AdblockRuleInfo>(r->content).props.test(DnsFilter::DARP_EXCEPTION);
    }));
    ASSERT_TRUE(r.rewritten_info.has_value());
}

} // namespace ag::dns::dnsfilter::test
