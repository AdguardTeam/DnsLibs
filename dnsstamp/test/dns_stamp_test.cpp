#include <algorithm>
#include <charconv>
#include <cstdint>
#include <functional>
#include <iterator>
#include <string_view>
#include <vector>

#include <gtest/gtest.h>

#ifdef _WIN32
#include <winsock2.h>
#endif

#include "dns/dnsstamp/dns_stamp.h"

namespace ag::dns::test {

// generated with:
// openssl x509 -noout -fingerprint -sha256 -inform pem -in /etc/ssl/certs/Go_Daddy_Class_2_CA.pem
static constexpr const auto pk_str =
        "C3:84:6B:F2:4B:9E:93:CA:64:27:4C:0E:C6:7C:1E:CC:5E:02:4F:FC:AC:D2:D7:40:19:35:0E:81:FE:54:6A:E4";

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

TEST_F(DnsstampTest, TestPlainUrlStampCreate) {
    struct TestData {
        std::string_view input;
        std::string_view expected;
    };
    static constexpr TestData data[] = {
            {.input = "https://dns.adguard-dns.com/dns-query", .expected = "https://dns.adguard-dns.com/dns-query"},
            {.input = "tls://[2a00:5a60::ad2:0ff]:5443/dns-query", .expected = "tls://[2a00:5a60::ad2:ff]:5443"},
            {.input = "quic://1.1.1.1:1080/dns-query", .expected = "quic://1.1.1.1:1080"},
    };
    for (const auto &[input, expected] : data) {
        const auto stamp = ServerStamp::from_string(input);
        ASSERT_FALSE(stamp.has_error()) << stamp.error()->str() << " (" << input << ")";
        ASSERT_EQ(expected, stamp->pretty_url(/*pretty_dnscrypt=*/true));
        ASSERT_EQ(expected, stamp->str());
    }
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
        // Bad only port address (:5443): DNSCrypt stamps require a server address
        {"sdns://"
         "AQIAAAAAAAAABTo1NDQzIIHQAtNqTKUMRzt0eWUP4S4CsyHLYThWKiCOQD39xV6UIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndW"
         "FyZC5jb20",
                nullptr},
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
    static constexpr auto expected =
            "sdns://"
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
    stamp.props = ServerInformalProperties{};
    test_server_stamp_create(stamp, expected);
}

TEST_F(DnsstampTest, TestDohStampParse) {
    // Google DoH
    static constexpr auto stamp_str =
            "sdns://AgUAAAAAAAAAACAe9iTP_15r07rd8_3b_epWVGfjdymdx-5mdRZvMAzBuQ5kbnMuZ29vZ2xlLmNvbQ0vZXhwZXJpbWVudGFs";
    test_server_stamp_parse(stamp_str, [](const auto &stamp) {
        return stamp.proto == StampProtoType::DOH && stamp.provider_name == "dns.google.com"
                && stamp.path == "/experimental";
    });
}

TEST_F(DnsstampWithPk1Test, TestDotStamp) {
    static constexpr auto expected =
            "sdns://AwcAAAAAAAAACTEyNy4wLjAuMSDDhGvyS56TymQnTA7GfB7MXgJP_KzS10AZNQ6B_lRq5AtleGFtcGxlLmNvbQ";
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
    stamp.props = ServerInformalProperties{};
    test_server_stamp_create(stamp, expected);
}

TEST_F(DnsstampWithPk1Test, TestDoqStamp) {
    static constexpr auto expected =
            "sdns://BAcAAAAAAAAACTEyNy4wLjAuMSDDhGvyS56TymQnTA7GfB7MXgJP_KzS10AZNQ6B_lRq5AtleGFtcGxlLmNvbQ";
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
    stamp.props = ServerInformalProperties{};
    test_server_stamp_create(stamp, expected);
}

TEST_F(DnsstampTest, TestDoqOnlyPort) {
    static constexpr auto expected = "sdns://BAAAAAAAAAAABTo3ODQ0AA9kbnMuYWRndWFyZC5jb20";
    ServerStamp stamp{};
    stamp.proto = StampProtoType::DOQ;
    stamp.provider_name = "dns.adguard.com";
    stamp.server_addr_str = ":7844";
    stamp.props = ServerInformalProperties{};
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
                    .ugly = "sdns://"
                            "BAcAAAAAAAAACTEyNy4wLjAuMSDDhGvyS56TymQnTA7GfB7MXgJP_KzS10AZNQ6B_lRq5AtleGFtcGxlLmNvbQ",
                    .pretty = "quic://example.com",
            },
            {
                    .ugly = "sdns://AwAAAAAAAAAAAAAPZG5zLmFkZ3VhcmQuY29t",
                    .pretty = "tls://dns.adguard.com",
            },
            {
                    .ugly = "sdns://"
                            "AwcAAAAAAAAACTEyNy4wLjAuMSDDhGvyS56TymQnTA7GfB7MXgJP_KzS10AZNQ6B_lRq5AtleGFtcGxlLmNvbQ",
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

TEST_F(DnsstampTest, TestStampParseDOH) {
#ifdef _WIN32
    WSADATA wsa_data = {};
    ASSERT_EQ(0, WSAStartup(MAKEWORD(2, 2), &wsa_data));
#endif

    struct TestCase {
        std::string_view input;
        std::string_view expected_server_addr_str;
        StampProtoType expected_proto;
        std::string_view expected_provider;
        std::string_view expected_path;
    };

    std::vector<TestCase> test_cases = {
            {"https://example.com:443/dns-query", "example.com", StampProtoType::DOH, "example.com", "/dns-query"},
            {"https://example.com:3129/dns-query", "example.com:3129", StampProtoType::DOH, "example.com",
                    "/dns-query"},
            {"https://example.com", "example.com", StampProtoType::DOH, "example.com", "/"},
            {"h3://example.com:443/dns-query", "example.com:443", StampProtoType::DOH, "example.com", "/dns-query"},
            {"h3://example.com:3129/dns-query", "example.com:3129", StampProtoType::DOH, "example.com", "/dns-query"},
            {"h3://example.com", "example.com", StampProtoType::DOH, "example.com", ""},
            {"https://8.8.8.8", "8.8.8.8", StampProtoType::DOH, "8.8.8.8", "/"},
            {"https://8.8.8.8:3129/dns-query", "8.8.8.8:3129", StampProtoType::DOH, "8.8.8.8", "/dns-query"},
            {"https://[2001:4860:4860::8888]", "[2001:4860:4860::8888]", StampProtoType::DOH, "[2001:4860:4860::8888]",
                    "/"},
    };

    for (const auto &tc : test_cases) {
        SCOPED_TRACE("Testing input: " + std::string(tc.input));
        test_server_stamp_parse(tc.input.data(), [&](const auto &stamp) {
            return stamp.proto == tc.expected_proto && stamp.server_addr_str == tc.expected_server_addr_str
                    && stamp.provider_name == tc.expected_provider && stamp.path == tc.expected_path;
        });
    }
}

TEST_F(DnsstampTest, TestStampParseTLS) {
    const auto stamp_str = "tls://example.com:853";
    test_server_stamp_parse(stamp_str, [](const auto &stamp) {
        return stamp.proto == StampProtoType::TLS && stamp.provider_name == "example.com"
                && stamp.server_addr_str == "example.com:853";
    });
}

TEST_F(DnsstampTest, TestStampParseDoq) {
    const auto stamp_str = "quic://example.com:853";
    test_server_stamp_parse(stamp_str, [](const auto &stamp) {
        return stamp.proto == StampProtoType::DOQ && stamp.provider_name == "example.com"
                && stamp.server_addr_str == "example.com:853";
    });
}

TEST_F(DnsstampTest, TestStampParsePlain) {
#ifdef _WIN32
    WSADATA wsa_data = {};
    ASSERT_EQ(0, WSAStartup(MAKEWORD(2, 2), &wsa_data));
#endif

    struct TestCase {
        std::string_view input;
        std::string_view expected_server_addr_str;
        StampProtoType expected_proto;
    };

    std::vector<TestCase> test_cases = {
            {"udp://example.com", "example.com", StampProtoType::PLAIN},
            {"udp://example.com:53", "example.com:53", StampProtoType::PLAIN},
            {"tcp://example.com", "example.com", StampProtoType::PLAIN},
            {"tcp://example.com:53", "example.com:53", StampProtoType::PLAIN},
            {"8.8.8.8", "8.8.8.8:0", StampProtoType::PLAIN},
            {"2001:4860:4860::8888", "[2001:4860:4860::8888]:0", StampProtoType::PLAIN},
            {"[2001:4860:4860::8888]", "[2001:4860:4860::8888]:0", StampProtoType::PLAIN},
            {"8.8.8.8:5353", "8.8.8.8:5353", StampProtoType::PLAIN},
            {"[2001:4860:4860::8888]:5353", "[2001:4860:4860::8888]:5353", StampProtoType::PLAIN},
    };

    for (const auto &tc : test_cases) {
        SCOPED_TRACE("Testing input: " + std::string(tc.input));
        test_server_stamp_parse(tc.input.data(), [&](const auto &stamp) {
            return stamp.proto == tc.expected_proto && stamp.server_addr_str == tc.expected_server_addr_str;
        });
    }
}

TEST_F(DnsstampTest, TestPrettyUrl) {
    const auto stamp_str = "tls://example.com";
    test_server_stamp_parse(stamp_str, [](const auto &stamp) {
        return stamp.pretty_url(false) == "tls://example.com";
    });
}

TEST_F(DnsstampTest, TestPrettyUrlWithPort) {
    const auto stamp_str = "quic://example.com:7844";
    test_server_stamp_parse(stamp_str, [](const auto &stamp) {
        return stamp.pretty_url(false) == "quic://example.com:7844";
    });
}

TEST_F(DnsstampTest, TestInvalids) {
    std::vector<std::string_view> test_cases = {"ftp://example.com", "socks5://example.com",
            "https://example.com:99999", "example.com", "example.com:433", "https://", "asdf.asdf.asdf", "8.8.8.260",
            "8.8.260.8", "8.260.8.8", "260.8.8.8", "8.8.8.8:99999", "https://8.8.8.260", "https://260.8.8.8",
            "https://8.8.8.8:99999", "2001:4860:4860::8888]", "[2001:4860:4860::8888", "2001:4860:kfff::8888",
            "[2001:4860:4860::8888]:99999", "https://2001:4860:4860::8888]", "https://[2001:4860:4860::8888",
            "https://2001:4860:kfff::8888", "https://[2001:4860:4860::8888]:99999"};

    for (const auto &tc : test_cases) {
        SCOPED_TRACE("Testing input: " + std::string(tc));
        test_server_stamp_parse(tc.data(), nullptr);
    }
}

static void expect_from_string_error(std::string_view input, ServerStamp::FromStringError expected) {
    SCOPED_TRACE("Testing input: " + std::string(input));
    auto result = ServerStamp::from_string(input);
    ASSERT_TRUE(result.has_error());
    ASSERT_EQ(expected, result.error()->value());
}

TEST_F(DnsstampTest, TestUrlWithoutHostRejected) {
    static constexpr std::string_view test_cases[] = {
            "tls://",
            "quic://",
            "h3://",
            "h3:///dns-query",
            "tls:///dns-query",
            "udp://",
            "tcp://",
    };
    for (const auto &tc : test_cases) {
        expect_from_string_error(tc, ServerStamp::FromStringError::AE_INVALID_HOST_PORT_FORMAT);
    }
}

struct AddrHostname {
    std::string_view server_addr;
    std::string_view provider_name;
};

static ServerStamp make_stamp(StampProtoType proto, const AddrHostname &fields, const Uint8Vector &pk) {
    ServerStamp stamp{};
    stamp.proto = proto;
    stamp.props = ServerInformalProperties{};
    stamp.server_addr_str = fields.server_addr;
    stamp.provider_name = fields.provider_name;
    if (proto == StampProtoType::DNSCRYPT) {
        stamp.server_pk = pk;
    } else {
        stamp.hashes = {pk};
    }
    if (proto == StampProtoType::DOH) {
        stamp.path = "/dns-query";
    }
    return stamp;
}

TEST_F(DnsstampWithPk1Test, TestDnscryptStampWithoutAddressOrProviderNameRejected) {
    static constexpr AddrHostname test_cases[] = {
            {"", "2.dnscrypt-cert.example.com"},
            {":5443", "2.dnscrypt-cert.example.com"},
            // The addresses are long enough for the stamp to pass the minimum size check
            {"[2001:db8:1234:5678::abcd]", ""},
            {"[2001:db8:1234:5678::abcd]:5443", ""},
            {"[2001:db8:1234:5678::abcd]:5443", ":443"},
            // Port in both the address and the provider name
            {"1.2.3.4:5443", "2.dnscrypt-cert.example.com:443"},
    };
    for (const auto &tc : test_cases) {
        SCOPED_TRACE(AG_FMT("addr='{}' provider='{}'", tc.server_addr, tc.provider_name));
        expect_from_string_error(
                make_stamp(StampProtoType::DNSCRYPT, tc, pk1).str(), ServerStamp::FromStringError::AE_INVALID_STAMP);
    }
}

TEST_F(DnsstampWithPk1Test, TestEncryptedStampWithoutHostnameRejected) {
    static constexpr AddrHostname test_cases[] = {
            {"", ""},
            {"127.0.0.1", ""},
            {"127.0.0.1:853", ""},
            {":853", ""},
            {"", ":853"},
            {"127.0.0.1", ":853"},
    };
    for (auto proto : {StampProtoType::DOH, StampProtoType::TLS, StampProtoType::DOQ}) {
        for (const auto &tc : test_cases) {
            SCOPED_TRACE(AG_FMT("proto={} addr='{}' hostname='{}'", (int) proto, tc.server_addr, tc.provider_name));
            expect_from_string_error(make_stamp(proto, tc, pk1).str(), ServerStamp::FromStringError::AE_INVALID_STAMP);
        }
    }
}

TEST_F(DnsstampWithPk1Test, TestEncryptedStampWithPortInBothFieldsRejected) {
    static constexpr AddrHostname test_cases[] = {
            {":853", "example.com:853"},
            {"127.0.0.1:853", "example.com:853"},
            {"127.0.0.1:853", "example.com:5443"},
            {"[::1]:853", "[::1]:853"},
    };
    for (auto proto : {StampProtoType::DOH, StampProtoType::TLS, StampProtoType::DOQ}) {
        for (const auto &tc : test_cases) {
            SCOPED_TRACE(AG_FMT("proto={} addr='{}' hostname='{}'", (int) proto, tc.server_addr, tc.provider_name));
            expect_from_string_error(make_stamp(proto, tc, pk1).str(), ServerStamp::FromStringError::AE_INVALID_STAMP);
        }
    }
}

TEST_F(DnsstampWithPk1Test, TestDnscryptProviderNameWithPortRejected) {
    static constexpr AddrHostname test_cases[] = {
            {"1.2.3.4", "2.dnscrypt-cert.example.com:443"},
            {"1.2.3.4:5443", "2.dnscrypt-cert.example.com:443"},
            {"[2001:db8::1]", "2.dnscrypt-cert.example.com:abc"},
    };
    for (const auto &tc : test_cases) {
        SCOPED_TRACE(AG_FMT("addr='{}' provider='{}'", tc.server_addr, tc.provider_name));
        expect_from_string_error(
                make_stamp(StampProtoType::DNSCRYPT, tc, pk1).str(), ServerStamp::FromStringError::AE_INVALID_STAMP);
    }
}

static constexpr std::string_view INVALID_PORTS[] = {"0", "00", "abc", "53a", "65536", "-1", "+53", " 53", "0x35"};

TEST_F(DnsstampWithPk1Test, TestInvalidHostnamePortRejected) {
    for (std::string_view port : INVALID_PORTS) {
        std::string hostname_with_port = AG_FMT("example.com:{}", port);
        for (auto proto : {StampProtoType::DOH, StampProtoType::TLS, StampProtoType::DOQ}) {
            for (const AddrHostname &tc :
                    {AddrHostname{"1.2.3.4", hostname_with_port}, AddrHostname{"", hostname_with_port}}) {
                SCOPED_TRACE(AG_FMT("proto={} addr='{}' hostname='{}'", (int) proto, tc.server_addr, tc.provider_name));
                expect_from_string_error(
                        make_stamp(proto, tc, pk1).str(), ServerStamp::FromStringError::AE_INVALID_PORT);
            }
        }
    }
}

TEST_F(DnsstampWithPk1Test, TestInvalidAddressPortRejected) {
    for (std::string_view port : INVALID_PORTS) {
        for (std::string addr : {AG_FMT("1.2.3.4:{}", port), AG_FMT(":{}", port)}) {
            for (auto proto : {StampProtoType::DOH, StampProtoType::TLS, StampProtoType::DOQ, StampProtoType::PLAIN,
                         StampProtoType::DNSCRYPT}) {
                if (addr.front() == ':' && (proto == StampProtoType::PLAIN || proto == StampProtoType::DNSCRYPT)) {
                    continue; // Already rejected for the missing address
                }
                std::string_view hostname =
                        (proto == StampProtoType::DNSCRYPT) ? "2.dnscrypt-cert.example.com" : "example.com";
                SCOPED_TRACE(AG_FMT("proto={} addr='{}' hostname='{}'", (int) proto, addr, hostname));
                expect_from_string_error(
                        make_stamp(proto, {addr, hostname}, pk1).str(), ServerStamp::FromStringError::AE_INVALID_PORT);
            }
        }
    }
}

TEST_F(DnsstampWithPk1Test, TestBoundaryPortsAccepted) {
    for (std::string_view port : {"1", "65535"}) {
        std::string addr_with_port = AG_FMT("1.2.3.4:{}", port);
        std::string hostname_with_port = AG_FMT("example.com:{}", port);
        for (auto proto : {StampProtoType::DOH, StampProtoType::TLS, StampProtoType::DOQ}) {
            for (const AddrHostname &tc :
                    {AddrHostname{addr_with_port, "example.com"}, AddrHostname{"1.2.3.4", hostname_with_port}}) {
                SCOPED_TRACE(AG_FMT("proto={} addr='{}' hostname='{}'", (int) proto, tc.server_addr, tc.provider_name));
                auto result = ServerStamp::from_string(make_stamp(proto, tc, pk1).str());
                ASSERT_FALSE(result.has_error()) << result.error()->str();
            }
        }
        for (auto proto : {StampProtoType::PLAIN, StampProtoType::DNSCRYPT}) {
            SCOPED_TRACE(AG_FMT("proto={} addr='{}'", (int) proto, addr_with_port));
            auto result = ServerStamp::from_string(
                    make_stamp(proto, {addr_with_port, "2.dnscrypt-cert.example.com"}, pk1).str());
            ASSERT_FALSE(result.has_error()) << result.error()->str();
        }
    }
}

// The port may come from either the address or the hostname, and the pretty URL uses it.
TEST_F(DnsstampWithPk1Test, TestEncryptedStampHostnameAndPortAccepted) {
    struct TestCase {
        AddrHostname fields;
        std::string_view expected_host_port;
    };
    static constexpr TestCase test_cases[] = {
            {{"", "example.com"}, "example.com"},
            {{"127.0.0.1", "example.com"}, "example.com"},
            {{"127.0.0.1:5443", "example.com"}, "example.com:5443"},
            {{":5443", "example.com"}, "example.com:5443"},
            {{"", "example.com:5443"}, "example.com:5443"},
            {{"127.0.0.1", "example.com:5443"}, "example.com:5443"},
            {{"[::1]", "[::1]:5443"}, "[::1]:5443"},
    };
    for (auto proto : {StampProtoType::DOH, StampProtoType::TLS, StampProtoType::DOQ}) {
        std::string_view scheme = (proto == StampProtoType::DOH) ? "https://"
                : (proto == StampProtoType::TLS)                 ? "tls://"
                                                                 : "quic://";
        std::string_view path = (proto == StampProtoType::DOH) ? "/dns-query" : "";
        for (const auto &tc : test_cases) {
            SCOPED_TRACE(AG_FMT(
                    "proto={} addr='{}' hostname='{}'", (int) proto, tc.fields.server_addr, tc.fields.provider_name));
            ServerStamp stamp = make_stamp(proto, tc.fields, pk1);
            auto result = ServerStamp::from_string(stamp.str());
            ASSERT_FALSE(result.has_error()) << result.error()->str();
            ASSERT_EQ(stamp.str(), result->str());
            ASSERT_EQ(AG_FMT("{}{}{}", scheme, tc.expected_host_port, path), result->pretty_url(true));
        }
    }
}

// Certificate hashes must be exactly SHA256_DIGEST_LENGTH bytes long: shorter
// ones used to be read out of bounds when building the upstream fingerprints.
TEST_F(DnsstampWithPk1Test, TestInvalidHashLengthRejected) {
    const Uint8Vector valid_hash(32, 0xab);
    const std::vector<std::vector<Uint8Vector>> test_cases = {
            {Uint8Vector(1, 0xab)},
            {Uint8Vector(4, 0xab)},
            {Uint8Vector(31, 0xab)},
            {Uint8Vector(33, 0xab)},
            {Uint8Vector(64, 0xab)},
            {valid_hash, Uint8Vector(4, 0xab)},
            {Uint8Vector(4, 0xab), valid_hash},
    };
    for (auto proto : {StampProtoType::DOH, StampProtoType::TLS, StampProtoType::DOQ}) {
        for (const auto &hashes : test_cases) {
            ServerStamp stamp = make_stamp(proto, {"127.0.0.1", "example.com"}, pk1);
            stamp.hashes = hashes;
            std::string sizes;
            for (const auto &hash : hashes) {
                sizes += AG_FMT("{} ", hash.size());
            }
            SCOPED_TRACE(AG_FMT("proto={} hash sizes: {}", (int) proto, sizes));
            expect_from_string_error(stamp.str(), ServerStamp::FromStringError::AE_INVALID_STAMP);
        }
    }
}

TEST_F(DnsstampWithPk1Test, TestValidHashLengthAccepted) {
    const std::vector<std::vector<Uint8Vector>> test_cases = {
            {},
            {Uint8Vector(32, 0xab)},
            {Uint8Vector(32, 0xab), Uint8Vector(32, 0xcd)},
    };
    for (auto proto : {StampProtoType::DOH, StampProtoType::TLS, StampProtoType::DOQ}) {
        for (const auto &hashes : test_cases) {
            ServerStamp stamp = make_stamp(proto, {"127.0.0.1", "example.com"}, pk1);
            stamp.hashes = hashes;
            SCOPED_TRACE(AG_FMT("proto={} hash count: {}", (int) proto, hashes.size()));
            auto result = ServerStamp::from_string(stamp.str());
            ASSERT_FALSE(result.has_error()) << result.error()->str();
            ASSERT_EQ(hashes, result->hashes);
        }
    }
}

} // namespace ag::dns::test
