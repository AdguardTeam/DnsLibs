#include <gtest/gtest.h>
#include <ag_utils.h>
#include <ag_net_utils.h>
#include <ag_socket_address.h>

TEST(net_utils, generally_work) {
    ASSERT_TRUE(ag::utils::is_valid_ip6("::"));
    ASSERT_TRUE(ag::utils::is_valid_ip6("::1"));
    ASSERT_TRUE(ag::utils::is_valid_ip4("0.0.0.0"));
    ASSERT_TRUE(ag::utils::is_valid_ip4("127.0.0.1"));

    ASSERT_FALSE(ag::utils::is_valid_ip6("[::]:80"));
    ASSERT_FALSE(ag::utils::is_valid_ip6("[::1]:80"));
    ASSERT_FALSE(ag::utils::is_valid_ip6("45:67"));
    ASSERT_FALSE(ag::utils::is_valid_ip4("0.0.0.0:80"));
    ASSERT_FALSE(ag::utils::is_valid_ip4("127.0.0.1:80"));
    ASSERT_FALSE(ag::utils::is_valid_ip4("45:67"));
    ASSERT_FALSE(ag::utils::is_valid_ip6("[::]"));
    ASSERT_FALSE(ag::utils::is_valid_ip6("[::1]"));
    ASSERT_FALSE(ag::utils::is_valid_ip6("[1.2.3.4]"));

    ASSERT_FALSE(ag::utils::str_to_socket_address("127.0.0.1:a12").valid());
    ASSERT_FALSE(ag::utils::str_to_socket_address("127.0.0.1:12a").valid());
    ASSERT_FALSE(ag::utils::str_to_socket_address("[::1]:a12").valid());
    ASSERT_FALSE(ag::utils::str_to_socket_address("[::1]:12a").valid());

    ASSERT_TRUE(ag::utils::str_to_socket_address("127.0.0.1").valid());
    ASSERT_TRUE(ag::utils::str_to_socket_address("127.0.0.1:80").valid());
    ASSERT_TRUE(ag::utils::str_to_socket_address("::1").valid());
    ASSERT_TRUE(ag::utils::str_to_socket_address("[::1]").valid());
    ASSERT_TRUE(ag::utils::str_to_socket_address("[::1]:80").valid());
}
