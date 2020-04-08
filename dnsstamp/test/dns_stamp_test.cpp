#include <gtest/gtest.h>
#include <dns_stamp.h>
#include <algorithm>
#include <charconv>
#include <cstdint>
#include <functional>
#include <iterator>
#include <string_view>
#include <vector>

// generated with:
// openssl x509 -noout -fingerprint -sha256 -inform pem -in /etc/ssl/certs/Go_Daddy_Class_2_CA.pem
static constexpr const auto pk_str = "C3:84:6B:F2:4B:9E:93:CA:64:27:4C:0E:C6:7C:1E:CC:5E:02:4F:FC:AC:D2:D7:40:19:35:0E:81:FE:54:6A:E4";

static std::vector<uint8_t> to_bytes(std::string_view sv, char separator) {
    std::vector<uint8_t> bin;
    for (auto i = std::begin(sv), e = std::end(sv); i < e; ++i) {
        auto separator_i = std::find(i, e, separator);
        uint8_t y;
        if (std::from_chars(&*i, &*i + (separator_i - i), y, 16).ec != std::errc{}) {
            return {};
        }
        bin.emplace_back(y);
        i = separator_i;
    }
    return bin;
}

struct dnsstamp_test : ::testing::Test {};

class dnsstamp_with_pk1_test : public dnsstamp_test {
protected:
    void SetUp() override {
        pk1 = to_bytes(pk_str, ':');
    }
    void TearDown() override {
    }
    std::vector<uint8_t> pk1;
};

static void test_server_stamp_create(const ag::server_stamp &stamp, std::string_view expected) {
    auto stamp_str = stamp.str();
    ASSERT_EQ(stamp_str, expected);
    auto[parsed_stamp, err] = ag::server_stamp::from_string(stamp_str);
    ASSERT_FALSE(err);
    auto ps = parsed_stamp.str();
    ASSERT_EQ(ps, stamp_str);
}

using is_stamp_valid_function = std::function<bool(const ag::server_stamp &)>;

static void test_server_stamp_parse(const char *stamp_str,
                                    const is_stamp_valid_function &is_stamp_valid) {
    auto[stamp, err] = ag::server_stamp::from_string(stamp_str);
    if (is_stamp_valid) {
        ASSERT_FALSE(err) << *err;
        ASSERT_TRUE(is_stamp_valid(stamp));
    } else {
        ASSERT_TRUE(err);
    }
}

TEST_F(dnsstamp_with_pk1_test, test_dnscrypt_stamp_create) {
    // same as exampleStamp in dnscrypt-stamper
    static constexpr auto expected = "sdns://AQcAAAAAAAAACTEyNy4wLjAuMSDDhGvyS56TymQnTA7GfB7MXgJP_KzS10AZNQ6B_lRq5BkyLmRuc2NyeXB0LWNlcnQubG9jYWxob3N0";
    ag::server_stamp stamp{};
    stamp.props = ag::server_informal_properties{
        (uint64_t)ag::server_informal_properties::DNSSEC |
        (uint64_t)ag::server_informal_properties::NO_LOG |
        (uint64_t)ag::server_informal_properties::NO_FILTER
    };
    stamp.proto = ag::stamp_proto_type::DNSCRYPT;
    stamp.server_addr_str = "127.0.0.1";
    stamp.provider_name = "2.dnscrypt-cert.localhost";
    stamp.server_pk = pk1;
    test_server_stamp_create(stamp, expected);
}

template<typename... Ts>
struct dnsstamp_param_test : dnsstamp_test, ::testing::WithParamInterface<Ts...> {};

struct dnscrypt_stamp_parse {
    const char *stamp_str;
    const char *server_addr_str_opt;
};

static const dnscrypt_stamp_parse test_dnscrypt_stamp_parse_data[]{
    // Good AdGuard DNSCrypt IPv4 (176.103.130.130)
    {
        "sdns://AQIAAAAAAAAADzE3Ni4xMDMuMTMwLjEzMCDRK0fyUtzywrv4mRCG6vec5EldixbIoMQyLlLKPzkIcyIyLmRuc2NyeXB0LmRlZmF1bHQubnMxLmFkZ3VhcmQuY29t",
        "176.103.130.130:443"
    },
    // Good AdGuard DNSCrypt [IPv6] ([2a00:5a60::ad2:0ff])
    {
        "sdns://AQIAAAAAAAAAFFsyYTAwOjVhNjA6OmFkMjowZmZdIIHQAtNqTKUMRzt0eWUP4S4CsyHLYThWKiCOQD39xV6UIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20",
        "[2a00:5a60::ad2:0ff]:443"
    },
    // Good AdGuard DNSCrypt IPv4:port (176.103.130.130:5443)
    {
        "sdns://AQIAAAAAAAAAFDE3Ni4xMDMuMTMwLjEzMDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20",
        "176.103.130.130:5443"
    },
    // Good AdGuard DNSCrypt [IPv6]:port ([2a00:5a60::ad2:0ff]:5443)
    {
        "sdns://AQIAAAAAAAAAGVsyYTAwOjVhNjA6OmFkMjowZmZdOjU0NDMggdAC02pMpQxHO3R5ZQ_hLgKzIcthOFYqII5APf3FXpQiMi5kbnNjcnlwdC5kZWZhdWx0Lm5zMS5hZGd1YXJkLmNvbQ",
        "[2a00:5a60::ad2:0ff]:5443"
    },
    // Bad AdGuard DNSCrypt IPv6 (2a00:5a60::ad2:0ff)
    {
        "sdns://AQIAAAAAAAAAEjJhMDA6NWE2MDo6YWQyOjBmZiCB0ALTakylDEc7dHllD-EuArMhy2E4ViogjkA9_cVelCIyLmRuc2NyeXB0LmRlZmF1bHQubnMxLmFkZ3VhcmQuY29t",
        nullptr // IPv6 strings must be included in square brackets
    },
    // Bad with colon at end (176.103.130.130:)
    {
        "sdns://AQIAAAAAAAAAEDE3Ni4xMDMuMTMwLjEzMDog0StH8lLc8sK7-JkQhur3nORJXYsWyKDEMi5Syj85CHMiMi5kbnNjcnlwdC5kZWZhdWx0Lm5zMS5hZGd1YXJkLmNvbQ",
        nullptr
    },
    // Bad with colon at end ([2a00:5a60::ad2:0ff]:)
    {
        "sdns://AQIAAAAAAAAAFVsyYTAwOjVhNjA6OmFkMjowZmZdOiCB0ALTakylDEc7dHllD-EuArMhy2E4ViogjkA9_cVelCIyLmRuc2NyeXB0LmRlZmF1bHQubnMxLmFkZ3VhcmQuY29t",
        nullptr
    },
    // Good only port address (:5443)
    {
        "sdns://AQIAAAAAAAAABTo1NDQzIIHQAtNqTKUMRzt0eWUP4S4CsyHLYThWKiCOQD39xV6UIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20",
        ":5443" // TODO Addresses with only port not allowed in DNSCrypt stamps (but allowed for DoH, DoT stamps)
    },
};

struct dnscrypt_stamp_parse_test : dnsstamp_param_test<dnscrypt_stamp_parse> {};

TEST_P(dnscrypt_stamp_parse_test, test_dnscrypt_stamp_parse) {
    const auto &p = GetParam();
    auto is_stamp_valid = [&](const auto &stamp) {
        return stamp.proto == ag::stamp_proto_type::DNSCRYPT &&
               stamp.provider_name == "2.dnscrypt.default.ns1.adguard.com" &&
               stamp.server_addr_str == p.server_addr_str_opt;
    };
    test_server_stamp_parse(p.stamp_str, p.server_addr_str_opt ? is_stamp_valid : is_stamp_valid_function());
}

INSTANTIATE_TEST_CASE_P(dnscrypt_stamp_parse_test, dnscrypt_stamp_parse_test,
                        ::testing::ValuesIn(test_dnscrypt_stamp_parse_data));

TEST_F(dnsstamp_with_pk1_test, test_doh_stamp) {
    static constexpr auto expected = "sdns://AgcAAAAAAAAACTEyNy4wLjAuMSDDhGvyS56TymQnTA7GfB7MXgJP_KzS10AZNQ6B_lRq5AtleGFtcGxlLmNvbQovZG5zLXF1ZXJ5";
    ag::server_stamp stamp{};
    stamp.props = ag::server_informal_properties{
        (uint64_t)ag::server_informal_properties::DNSSEC |
        (uint64_t)ag::server_informal_properties::NO_LOG |
        (uint64_t)ag::server_informal_properties::NO_FILTER
    };
    stamp.server_addr_str = "127.0.0.1";
    stamp.proto = ag::stamp_proto_type::DOH;
    stamp.provider_name = "example.com";
    stamp.hashes = {{pk1}};
    stamp.path = "/dns-query";
    test_server_stamp_create(stamp, expected);
}

TEST_F(dnsstamp_test, test_doh_short_stamp) {
    static constexpr auto expected = "sdns://AgAAAAAAAAAAAAALZXhhbXBsZS5jb20KL2Rucy1xdWVyeQ";
    ag::server_stamp stamp{};
    stamp.proto = ag::stamp_proto_type::DOH;
    stamp.provider_name = "example.com";
    stamp.path = "/dns-query";
    test_server_stamp_create(stamp, expected);
}

TEST_F(dnsstamp_test, test_doh_stamp_parse) {
    // Google DoH
    static constexpr auto stamp_str = "sdns://AgUAAAAAAAAAACAe9iTP_15r07rd8_3b_epWVGfjdymdx-5mdRZvMAzBuQ5kbnMuZ29vZ2xlLmNvbQ0vZXhwZXJpbWVudGFs";
    test_server_stamp_parse(stamp_str, [](const auto &stamp) {
        return stamp.proto == ag::stamp_proto_type::DOH &&
               stamp.provider_name == "dns.google.com" &&
               stamp.path == "/experimental";
    });
}

TEST_F(dnsstamp_with_pk1_test, test_dot_stamp) {
    static constexpr auto expected = "sdns://AwcAAAAAAAAACTEyNy4wLjAuMSDDhGvyS56TymQnTA7GfB7MXgJP_KzS10AZNQ6B_lRq5AtleGFtcGxlLmNvbQ";
    ag::server_stamp stamp{};
    stamp.props = ag::server_informal_properties{
        (uint64_t)ag::server_informal_properties::DNSSEC |
        (uint64_t)ag::server_informal_properties::NO_LOG |
        (uint64_t)ag::server_informal_properties::NO_FILTER
    };
    stamp.server_addr_str = "127.0.0.1";
    stamp.proto = ag::stamp_proto_type::TLS;
    stamp.provider_name = "example.com";
    stamp.hashes = {{pk1}};
    test_server_stamp_create(stamp, expected);
}

TEST_F(dnsstamp_test, test_dot_short_stamp) {
    static constexpr auto expected = "sdns://AwAAAAAAAAAAAAAPZG5zLmFkZ3VhcmQuY29t";
    ag::server_stamp stamp{};
    stamp.proto = ag::stamp_proto_type::TLS;
    stamp.provider_name = "dns.adguard.com";
    test_server_stamp_create(stamp, expected);
}

TEST_F(dnsstamp_test, test_plain_stamp) {
    static constexpr auto expected = "sdns://AAcAAAAAAAAABzguOC44Ljg";
    ag::server_stamp stamp{};
    stamp.props = ag::server_informal_properties{
        (uint64_t)ag::server_informal_properties::DNSSEC |
        (uint64_t)ag::server_informal_properties::NO_LOG |
        (uint64_t)ag::server_informal_properties::NO_FILTER
    };
    stamp.server_addr_str = "127.0.0.1";
    stamp.proto = ag::stamp_proto_type::PLAIN;
    stamp.server_addr_str = "8.8.8.8";
    test_server_stamp_create(stamp, expected);
}
