#include <algorithm>
#include <charconv>
#include <cstdint>
#include <functional>
#include <iterator>
#include <string_view>
#include <vector>

#include "dns/dnsstamp/dns_stamp.h"
#include <gtest/gtest.h>

namespace ag::dns::test {

// generated with:
// openssl x509 -noout -fingerprint -sha256 -inform pem -in /etc/ssl/certs/Go_Daddy_Class_2_CA.pem
static constexpr const auto pk_str
        = "C3:84:6B:F2:4B:9E:93:CA:64:27:4C:0E:C6:7C:1E:CC:5E:02:4F:FC:AC:D2:D7:40:19:35:0E:81:FE:54:6A:E4";

static Uint8Vector to_bytes(std::string_view sv, char separator) {
    Uint8Vector bin;
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

struct DnsstampTest : ::testing::Test {};

class DnsstampWithPk1Test : public DnsstampTest {
protected:
    void SetUp() override {
        pk1 = to_bytes(pk_str, ':');
    }
    void TearDown() override {
    }
    Uint8Vector pk1;
};

static void test_server_stamp_create(const ServerStamp &stamp, std::string_view expected) {
    auto stamp_str = stamp.str();
    ASSERT_EQ(stamp_str, expected);
    auto parse_result = ServerStamp::from_string(stamp_str);
    ASSERT_FALSE(parse_result.has_error());
    auto ps = parse_result->str();
    ASSERT_EQ(ps, stamp_str);
}

using IsStampValidFunction = std::function<bool(const ServerStamp &)>;

static void test_server_stamp_parse(const char *stamp_str, const IsStampValidFunction &is_stamp_valid) {
    auto parse_result = ServerStamp::from_string(stamp_str);
    if (is_stamp_valid) {
        ASSERT_FALSE(parse_result.has_error()) << parse_result.error()->str();
        ASSERT_TRUE(is_stamp_valid(parse_result.value()));
    } else {
        ASSERT_TRUE(parse_result.has_error());
    }
}

TEST_F(DnsstampWithPk1Test, TestDnscryptStampCreate) {
    // same as exampleStamp in dnscrypt-stamper
    static constexpr auto expected = "sdns://"
                                     "AQcAAAAAAAAACTEyNy4wLjAuMSDDhGvyS56TymQnTA7GfB7MXgJP_KzS10AZNQ6B_"
                                     "lRq5BkyLmRuc2NyeXB0LWNlcnQubG9jYWxob3N0";
    ServerStamp stamp{};
    stamp.props = ServerInformalProperties{(uint64_t) ServerInformalProperties::DNSSEC
            | (uint64_t) ServerInformalProperties::NO_LOG | (uint64_t) ServerInformalProperties::NO_FILTER};
    stamp.proto = StampProtoType::DNSCRYPT;
    stamp.server_addr_str = "127.0.0.1";
    stamp.provider_name = "2.dnscrypt-cert.localhost";
    stamp.server_pk = pk1;
    test_server_stamp_create(stamp, expected);
}

template <typename... Ts>
struct DnsstampParamTest : DnsstampTest, ::testing::WithParamInterface<Ts...> {};

struct DnscryptStampParse {
    const char *stamp_str;
    const char *server_addr_str_opt;
};

static const DnscryptStampParse test_dnscrypt_stamp_parse_data[]{
        // Good AdGuard DNSCrypt IPv4 (176.103.130.130)
        {"sdns://"
         "AQIAAAAAAAAADzE3Ni4xMDMuMTMwLjEzMCDRK0fyUtzywrv4mRCG6vec5EldixbIoMQyLlLKPzkIcyIyLmRuc2NyeXB0LmRlZmF1bHQubnMxL"
         "mFkZ3VhcmQuY29t",
                "176.103.130.130"},
        // Good AdGuard DNSCrypt [IPv6] ([2a00:5a60::ad2:0ff])
        {"sdns://"
         "AQIAAAAAAAAAFFsyYTAwOjVhNjA6OmFkMjowZmZdIIHQAtNqTKUMRzt0eWUP4S4CsyHLYThWKiCOQD39xV6UIjIuZG5zY3J5cHQuZGVmYXVsd"
         "C5uczEuYWRndWFyZC5jb20",
                "[2a00:5a60::ad2:0ff]"},
        // Good AdGuard DNSCrypt IPv4:port (176.103.130.130:5443)
        {"sdns://"
         "AQIAAAAAAAAAFDE3Ni4xMDMuMTMwLjEzMDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_"
         "OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20",
                "176.103.130.130:5443"},
        // Good AdGuard DNSCrypt [IPv6]:port ([2a00:5a60::ad2:0ff]:5443)
        {"sdns://"
         "AQIAAAAAAAAAGVsyYTAwOjVhNjA6OmFkMjowZmZdOjU0NDMggdAC02pMpQxHO3R5ZQ_"
         "hLgKzIcthOFYqII5APf3FXpQiMi5kbnNjcnlwdC5kZWZhdWx0Lm5zMS5hZGd1YXJkLmNvbQ",
                "[2a00:5a60::ad2:0ff]:5443"},
        // Bad AdGuard DNSCrypt IPv6 (2a00:5a60::ad2:0ff)
        {
                "sdns://"
                "AQIAAAAAAAAAEjJhMDA6NWE2MDo6YWQyOjBmZiCB0ALTakylDEc7dHllD-EuArMhy2E4ViogjkA9_"
                "cVelCIyLmRuc2NyeXB0LmRlZmF1bHQubnMxLmFkZ3VhcmQuY29t",
                nullptr // IPv6 strings must be included in square brackets
        },
        // Bad with colon at end (176.103.130.130:)
        {"sdns://"
         "AQIAAAAAAAAAEDE3Ni4xMDMuMTMwLjEzMDog0StH8lLc8sK7-"
         "JkQhur3nORJXYsWyKDEMi5Syj85CHMiMi5kbnNjcnlwdC5kZWZhdWx0Lm5zMS5hZGd1YXJkLmNvbQ",
                nullptr},
        // Bad with colon at end ([2a00:5a60::ad2:0ff]:)
        {"sdns://"
         "AQIAAAAAAAAAFVsyYTAwOjVhNjA6OmFkMjowZmZdOiCB0ALTakylDEc7dHllD-EuArMhy2E4ViogjkA9_"
         "cVelCIyLmRuc2NyeXB0LmRlZmF1bHQubnMxLmFkZ3VhcmQuY29t",
                nullptr},
        // Good only port address (:5443)
        {
                "sdns://"
                "AQIAAAAAAAAABTo1NDQzIIHQAtNqTKUMRzt0eWUP4S4CsyHLYThWKiCOQD39xV6UIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndW"
                "FyZC5jb20",
                ":5443" // TODO Addresses with only port not allowed in DNSCrypt stamps (but allowed for DoH, DoT
                        // stamps)
        },
};

struct DnscryptStampParseTest : DnsstampParamTest<DnscryptStampParse> {};

TEST_P(DnscryptStampParseTest, TestDnscryptStampParse) {
    const auto &p = GetParam();
    auto is_stamp_valid = [&](const auto &stamp) {
        return stamp.proto == StampProtoType::DNSCRYPT && stamp.provider_name == "2.dnscrypt.default.ns1.adguard.com"
                && stamp.server_addr_str == p.server_addr_str_opt;
    };
    test_server_stamp_parse(p.stamp_str, p.server_addr_str_opt ? is_stamp_valid : IsStampValidFunction{});
}

INSTANTIATE_TEST_SUITE_P(
        DnscryptStampParseTest, DnscryptStampParseTest, ::testing::ValuesIn(test_dnscrypt_stamp_parse_data));

TEST_F(DnsstampWithPk1Test, TestDohStamp) {
    static constexpr auto expected
            = "sdns://"
              "AgcAAAAAAAAACTEyNy4wLjAuMSDDhGvyS56TymQnTA7GfB7MXgJP_KzS10AZNQ6B_lRq5AtleGFtcGxlLmNvbQovZG5zLXF1ZXJ5";
    ServerStamp stamp{};
    stamp.props = ServerInformalProperties{(uint64_t) ServerInformalProperties::DNSSEC
            | (uint64_t) ServerInformalProperties::NO_LOG | (uint64_t) ServerInformalProperties::NO_FILTER};
    stamp.server_addr_str = "127.0.0.1";
    stamp.proto = StampProtoType::DOH;
    stamp.provider_name = "example.com";
    stamp.hashes = {{pk1}};
    stamp.path = "/dns-query";
    test_server_stamp_create(stamp, expected);
}

TEST_F(DnsstampTest, TestDohShortStamp) {
    static constexpr auto expected = "sdns://AgAAAAAAAAAAAAALZXhhbXBsZS5jb20KL2Rucy1xdWVyeQ";
    ServerStamp stamp{};
    stamp.proto = StampProtoType::DOH;
    stamp.provider_name = "example.com";
    stamp.path = "/dns-query";
    test_server_stamp_create(stamp, expected);
}

TEST_F(DnsstampTest, TestDohStampParse) {
    // Google DoH
    static constexpr auto stamp_str
            = "sdns://AgUAAAAAAAAAACAe9iTP_15r07rd8_3b_epWVGfjdymdx-5mdRZvMAzBuQ5kbnMuZ29vZ2xlLmNvbQ0vZXhwZXJpbWVudGFs";
    test_server_stamp_parse(stamp_str, [](const auto &stamp) {
        return stamp.proto == StampProtoType::DOH && stamp.provider_name == "dns.google.com"
                && stamp.path == "/experimental";
    });
}

TEST_F(DnsstampWithPk1Test, TestDotStamp) {
    static constexpr auto expected
            = "sdns://AwcAAAAAAAAACTEyNy4wLjAuMSDDhGvyS56TymQnTA7GfB7MXgJP_KzS10AZNQ6B_lRq5AtleGFtcGxlLmNvbQ";
    ServerStamp stamp{};
    stamp.props = ServerInformalProperties{(uint64_t) ServerInformalProperties::DNSSEC
            | (uint64_t) ServerInformalProperties::NO_LOG | (uint64_t) ServerInformalProperties::NO_FILTER};
    stamp.server_addr_str = "127.0.0.1";
    stamp.proto = StampProtoType::TLS;
    stamp.provider_name = "example.com";
    stamp.hashes = {{pk1}};
    test_server_stamp_create(stamp, expected);
}

TEST_F(DnsstampTest, TestDotShortStamp) {
    static constexpr auto expected = "sdns://AwAAAAAAAAAAAAAPZG5zLmFkZ3VhcmQuY29t";
    ServerStamp stamp{};
    stamp.proto = StampProtoType::TLS;
    stamp.provider_name = "dns.adguard.com";
    test_server_stamp_create(stamp, expected);
}

TEST_F(DnsstampWithPk1Test, TestDoqStamp) {
    static constexpr auto expected
            = "sdns://BAcAAAAAAAAACTEyNy4wLjAuMSDDhGvyS56TymQnTA7GfB7MXgJP_KzS10AZNQ6B_lRq5AtleGFtcGxlLmNvbQ";
    ServerStamp stamp{};
    stamp.props = ServerInformalProperties{(uint64_t) ServerInformalProperties::DNSSEC
            | (uint64_t) ServerInformalProperties::NO_LOG | (uint64_t) ServerInformalProperties::NO_FILTER};
    stamp.server_addr_str = "127.0.0.1";
    stamp.proto = StampProtoType::DOQ;
    stamp.provider_name = "example.com";
    stamp.hashes = {{pk1}};
    test_server_stamp_create(stamp, expected);
}

TEST_F(DnsstampTest, TestDoqShortStamp) {
    static constexpr auto expected = "sdns://BAAAAAAAAAAAAAAPZG5zLmFkZ3VhcmQuY29t";
    ServerStamp stamp{};
    stamp.proto = StampProtoType::DOQ;
    stamp.provider_name = "dns.adguard.com";
    test_server_stamp_create(stamp, expected);
}

TEST_F(DnsstampTest, TestDoqOnlyPort) {
    static constexpr auto expected = "sdns://BAAAAAAAAAAABTo3ODQ0AA9kbnMuYWRndWFyZC5jb20";
    ServerStamp stamp{};
    stamp.proto = StampProtoType::DOQ;
    stamp.provider_name = "dns.adguard.com";
    stamp.server_addr_str = ":7844";
    test_server_stamp_create(stamp, expected);
}

TEST_F(DnsstampTest, TestPlainStamp) {
    static constexpr auto expected = "sdns://AAcAAAAAAAAABzguOC44Ljg";
    ServerStamp stamp{};
    stamp.props = ServerInformalProperties{(uint64_t) ServerInformalProperties::DNSSEC
            | (uint64_t) ServerInformalProperties::NO_LOG | (uint64_t) ServerInformalProperties::NO_FILTER};
    stamp.proto = StampProtoType::PLAIN;
    stamp.server_addr_str = "8.8.8.8";
    test_server_stamp_create(stamp, expected);
}

TEST_F(DnsstampTest, TestPrettyUrlAndStr) {
    struct TestData {
        std::string_view ugly;
        std::string_view pretty;
        bool pretty_dnscrypt = true;
    };
    static constexpr TestData data[] = {
            {
                    .ugly = "sdns://AAcAAAAAAAAABzguOC44Ljg",
                    .pretty = "8.8.8.8",
            },
            {
                    .ugly = "sdns://AAcAAAAAAAAAGltmZTgwOjo2ZDZkOmY3MmM6M2FkOjYwYjhd",
                    .pretty = "fe80::6d6d:f72c:3ad:60b8",
            },
            {
                    .ugly = "sdns://BAAAAAAAAAAABTo3ODQ0AA9kbnMuYWRndWFyZC5jb20",
                    .pretty = "quic://dns.adguard.com:7844",
            },
            {
                    .ugly = "sdns://BAcAAAAAAAAADDk0LjE0MC4xNC4xNAAPZG5zLmFkZ3VhcmQuY29t",
                    .pretty = "quic://dns.adguard.com",
            },
            {
                    .ugly = "sdns://BAcAAAAAAAAAEDk0LjE0MC4xNC4xNDo4NTMAD2Rucy5hZGd1YXJkLmNvbQ",
                    .pretty = "quic://dns.adguard.com:853",
            },
            {
                    .ugly = "sdns://BAcAAAAAAAAAEDk0LjE0MC4xNC4xNDo3ODQAD2Rucy5hZGd1YXJkLmNvbQ",
                    .pretty = "quic://dns.adguard.com:784",
            },
            {
                    .ugly
                    = "sdns://BAcAAAAAAAAACTEyNy4wLjAuMSDDhGvyS56TymQnTA7GfB7MXgJP_KzS10AZNQ6B_lRq5AtleGFtcGxlLmNvbQ",
                    .pretty = "quic://example.com",
            },
            {
                    .ugly = "sdns://AwAAAAAAAAAAAAAPZG5zLmFkZ3VhcmQuY29t",
                    .pretty = "tls://dns.adguard.com",
            },
            {
                    .ugly
                    = "sdns://AwcAAAAAAAAACTEyNy4wLjAuMSDDhGvyS56TymQnTA7GfB7MXgJP_KzS10AZNQ6B_lRq5AtleGFtcGxlLmNvbQ",
                    .pretty = "tls://example.com",
            },
            {
                    .ugly = "sdns://AgAAAAAAAAAAAAALZXhhbXBsZS5jb20KL2Rucy1xdWVyeQ",
                    .pretty = "https://example.com/dns-query",
            },
            {
                    .ugly = "sdns://"
                            "AgcAAAAAAAAACTEyNy4wLjAuMSDDhGvyS56TymQnTA7GfB7MXgJP_KzS10AZNQ6B_"
                            "lRq5AtleGFtcGxlLmNvbQovZG5zLXF1ZXJ5",
                    .pretty = "https://example.com/dns-query",
            },
            {
                    .ugly = "sdns://"
                            "AgUAAAAAAAAAACAe9iTP_15r07rd8_3b_epWVGfjdymdx-"
                            "5mdRZvMAzBuQ5kbnMuZ29vZ2xlLmNvbQ0vZXhwZXJpbWVudGFs",
                    .pretty = "https://dns.google.com/experimental",
            },
            {.ugly = "sdns://"
                     "AQIAAAAAAAAADzE3Ni4xMDMuMTMwLjEzMCDRK0fyUtzywrv4mRCG6vec5EldixbIoMQyLlLKPzkIcyIyLmRuc2NyeXB0LmRlZ"
                     "mF1bHQubnMxLmFkZ3VhcmQuY29t",
                    .pretty = "dnscrypt://2.dnscrypt.default.ns1.adguard.com"},
            {
                    .ugly = "sdns://"
                            "AQIAAAAAAAAADzE3Ni4xMDMuMTMwLjEzMCDRK0fyUtzywrv4mRCG6vec5EldixbIoMQyLlLKPzkIcyIyLmRuc2NyeX"
                            "B0LmRlZmF1bHQubnMxLmFkZ3VhcmQuY29t",
                    .pretty = "sdns://"
                              "AQIAAAAAAAAADzE3Ni4xMDMuMTMwLjEzMCDRK0fyUtzywrv4mRCG6vec5EldixbIoMQyLlLKPzkIcyIyLmRuc2Ny"
                              "eXB0LmRlZmF1bHQubnMxLmFkZ3VhcmQuY29t",
                    .pretty_dnscrypt = false,
            },
    };
    for (auto &d : data) {
        auto stamp_result = ServerStamp::from_string(d.ugly);
        ASSERT_FALSE(stamp_result.has_error()) << stamp_result.error()->str() << " (" << d.ugly << ")";
        ASSERT_EQ(d.pretty, stamp_result->pretty_url(d.pretty_dnscrypt));
        ASSERT_EQ(d.ugly, stamp_result->str());
    }
}

} // namespace ag::test
