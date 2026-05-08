#include <gtest/gtest.h>

#include "dns/common/url_utils.h"

namespace ag::dns::test {

TEST(UrlUtils, MaskPasswordBasic) {
    EXPECT_EQ("https://user:***@host/path", mask_password("https://user:secret@host/path"));
}

TEST(UrlUtils, MaskPasswordWithPort) {
    EXPECT_EQ("https://user:***@host:443/dns-query", mask_password("https://user:pass@host:443/dns-query"));
}

TEST(UrlUtils, MaskPasswordEncodedChars) {
    EXPECT_EQ("https://user:***@host/path", mask_password("https://user:p%40ss@host/path"));
}

TEST(UrlUtils, MaskPasswordEmptyPassword) {
    EXPECT_EQ("https://user:***@host/path", mask_password("https://user:@host/path"));
}

TEST(UrlUtils, NoPasswordNoAt) {
    EXPECT_EQ("https://host/path", mask_password("https://host/path"));
}

TEST(UrlUtils, NoScheme) {
    EXPECT_EQ("8.8.8.8:53", mask_password("8.8.8.8:53"));
}

TEST(UrlUtils, TlsNoCredentials) {
    EXPECT_EQ("tls://host:853", mask_password("tls://host:853"));
}

TEST(UrlUtils, SdnsStamp) {
    EXPECT_EQ("sdns://AQIAAAAAAA", mask_password("sdns://AQIAAAAAAA"));
}

TEST(UrlUtils, QuicNoCredentials) {
    EXPECT_EQ("quic://dns.adguard.com:853", mask_password("quic://dns.adguard.com:853"));
}

TEST(UrlUtils, AtInPath) {
    // '@' after the path slash should not be treated as credentials separator
    EXPECT_EQ("https://host/path@something", mask_password("https://host/path@something"));
}

TEST(UrlUtils, CredentialsInPath) {
    // user:pass@bar after path slash — not authority credentials
    EXPECT_EQ("https://host/user:pass@bar", mask_password("https://host/user:pass@bar"));
}

TEST(UrlUtils, UsernameOnlyNoColon) {
    // Only username without ':' separator — no password to mask
    EXPECT_EQ("https://user@host/path", mask_password("https://user@host/path"));
}

} // namespace ag::dns::test
