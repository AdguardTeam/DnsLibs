#include "gtest/gtest.h"
#include "upstream_utils.h"
#include <magic_enum.hpp>

struct upstream_utils_test : ::testing::Test {};

struct parse_dns_stamp_data {
    std::string stamp_str;
    ag::stamp_proto_type proto; /** Protocol (0x00 for plain, 0x01 for DNSCrypt, 0x02 for DOH, 0x03 for DOT */
    std::string server_addr; /** Server address */
    std::string provider_name; /** Provider name */
    std::string path; /** Path (for DOH) */
};

struct parse_dns_stamp_test : upstream_utils_test, ::testing::WithParamInterface<parse_dns_stamp_data> {};

static parse_dns_stamp_data parse_dns_stamp_test_data[]{
    // Plain
    {
        "sdns://AAcAAAAAAAAABzguOC44Ljg",
        ag::stamp_proto_type::PLAIN,
        "8.8.8.8:53",
        "",
        "",
    },
    // AdGuard DNS (DNSCrypt)
    {
        "sdns://AQIAAAAAAAAAFDE3Ni4xMDMuMTMwLjEzMDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20",
        ag::stamp_proto_type::DNSCRYPT,
        "176.103.130.130:5443",
        "2.dnscrypt.default.ns1.adguard.com",
        "",
    },
    // DoH
    {
        "sdns://AgcAAAAAAAAACTEyNy4wLjAuMSDDhGvyS56TymQnTA7GfB7MXgJP_KzS10AZNQ6B_lRq5AtleGFtcGxlLmNvbQovZG5zLXF1ZXJ5",
        ag::stamp_proto_type::DOH,
        "127.0.0.1:443",
        "example.com",
        "/dns-query",
    },
    // DoT
    {
        "sdns://AwcAAAAAAAAACTEyNy4wLjAuMSDDhGvyS56TymQnTA7GfB7MXgJP_KzS10AZNQ6B_lRq5AtleGFtcGxlLmNvbQ",
        ag::stamp_proto_type::TLS,
        "127.0.0.1:853",
        "example.com",
        "",
    },
    // Plain (IPv6)
    {
        "sdns://AAcAAAAAAAAAGltmZTgwOjo2ZDZkOmY3MmM6M2FkOjYwYjhd",
        ag::stamp_proto_type::PLAIN,
        "[fe80::6d6d:f72c:3ad:60b8]:53",
        "",
    }
};

TEST_P(parse_dns_stamp_test, parse_dns_stamp) {
    const auto &p = GetParam();
    auto[stamp, err] = ag::parse_dns_stamp(p.stamp_str);
    ASSERT_FALSE(err) << "Cannot fail: " << *err;
    ASSERT_EQ(stamp.proto, p.proto) << "Wrong stamp proto: " << magic_enum::enum_name(stamp.proto);
    ASSERT_EQ(stamp.server_addr, p.server_addr) << "Wrong stamp server address: " << stamp.server_addr;
    ASSERT_EQ(stamp.provider_name, p.provider_name) << "Wrong stamp provider name: " << stamp.provider_name;
    ASSERT_EQ(stamp.path, p.path) << "Wrong stamp path: " << stamp.path;
}

INSTANTIATE_TEST_CASE_P(stamp_helper_test, parse_dns_stamp_test, testing::ValuesIn(parse_dns_stamp_test_data));

TEST_F(upstream_utils_test, test_upstream) {
    using namespace std::chrono_literals;

    static constexpr auto timeout = 500ms;
    auto err = ag::test_upstream({"123.12.32.1:1493", {}, timeout}, nullptr);
    ASSERT_TRUE(err) << "Cannot be successful";

    err = ag::test_upstream({"8.8.8.8:53", {}, 10 * timeout}, nullptr);
    ASSERT_FALSE(err) << "Cannot fail: " << *err;

    // Test for DoT with 2 bootstraps. Only one is valid
    // Use stub verifier b/c certificate verification is not part of the tested logic
    // and would fail on platforms where it is unsupported by ag::default_verifier
    err = ag::test_upstream({"tls://dns.adguard.com", {"1.2.3.4", "8.8.8.8"}, 10 * timeout},
                            [](const ag::certificate_verification_event &) { return std::nullopt; });
    ASSERT_FALSE(err) << "Cannot fail: " << *err;
}
