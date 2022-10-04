#include <curl/curl.h>
#include <gtest/gtest.h>

TEST(CurlFeatures, CurlSupportsHttp2) {
    auto *info = curl_version_info(CURLVERSION_NOW);
    ASSERT_NE(0, info->features & CURL_VERSION_HTTP2);
}

TEST(CurlFeatures, CurlSupportsHttp3) {
    auto *info = curl_version_info(CURLVERSION_NOW);
    ASSERT_NE(0, info->features & CURL_VERSION_HTTP3);
}
