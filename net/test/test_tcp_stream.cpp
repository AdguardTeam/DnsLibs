#include <gtest/gtest.h>
#include <ag_socket.h>
#include <ag_blocking_socket.h>
#include <ag_logger.h>


TEST(TcpStream, DISABLED_Blocking) {
    ag::socket_factory factory({});
    ag::blocking_socket socket(factory.make_socket({ ag::utils::TP_TCP }));
    ASSERT_TRUE(socket);

    auto e = socket.connect(
            { ag::socket_address("1.1.1.1", 80), std::chrono::seconds(1) });
    ASSERT_FALSE(e.has_value()) << e->description;

    std::string_view GET = "GET / HTTP/1.1\r\nHost: 1.1.1.1\r\n\r\n";
    e = socket.send({ (uint8_t *)GET.data(), GET.size() });
    ASSERT_FALSE(e.has_value()) << e->description;

    std::string received_data;
    e = socket.receive(
            {
                [] (void *arg, ag::uint8_view data) {
                    *(std::string *)arg = { (char *)data.data(), data.size() };
                    return false;
                },
                &received_data,
            },
            std::nullopt);
    ASSERT_FALSE(e.has_value()) << e->description;
    SPDLOG_INFO("Received data:\n{}", received_data);
}

TEST(TcpStream, DISABLED_HttpProxy) {
    ag::set_default_log_level(ag::TRACE);

    ag::outbound_proxy_settings proxy_settings = { ag::outbound_proxy_protocol::HTTP_CONNECT, "127.0.0.1", 3129 };
    ag::socket_factory factory({ &proxy_settings });
    ag::blocking_socket socket(factory.make_socket({ ag::utils::TP_TCP }));
    ASSERT_TRUE(socket);

    auto e = socket.connect(
            { ag::socket_address("1.1.1.1", 80), std::chrono::seconds(1) });
    ASSERT_FALSE(e.has_value()) << e->description;

    std::string_view GET = "GET / HTTP/1.1\r\nHost: 1.1.1.1\r\n\r\n";
    e = socket.send({ (uint8_t *)GET.data(), GET.size() });
    ASSERT_FALSE(e.has_value()) << e->description;

    std::string received_data;
    e = socket.receive(
            {
                    [] (void *arg, ag::uint8_view data) {
                        *(std::string *)arg = { (char *)data.data(), data.size() };
                        return false;
                    },
                    &received_data,
            },
            std::nullopt);
    ASSERT_FALSE(e.has_value()) << e->description;
    SPDLOG_INFO("Received data:\n{}", received_data);
}

TEST(TcpStream, DISABLED_SocksProxy) {
    ag::set_default_log_level(ag::TRACE);

    ag::outbound_proxy_settings proxy_settings = { ag::outbound_proxy_protocol::SOCKS5, "127.0.0.1", 8888 };
    ag::socket_factory factory({ &proxy_settings });
    ag::blocking_socket socket(factory.make_socket({ ag::utils::TP_TCP }));
    ASSERT_TRUE(socket);

    auto e = socket.connect(
            { ag::socket_address("1.1.1.1", 80), std::chrono::seconds(1) });
    ASSERT_FALSE(e.has_value()) << e->description;

    std::string_view GET = "GET / HTTP/1.1\r\nHost: 1.1.1.1\r\n\r\n";
    e = socket.send({ (uint8_t *)GET.data(), GET.size() });
    ASSERT_FALSE(e.has_value()) << e->description;

    std::string received_data;
    e = socket.receive(
            {
                    [] (void *arg, ag::uint8_view data) {
                        *(std::string *)arg = { (char *)data.data(), data.size() };
                        return false;
                    },
                    &received_data,
            },
            std::nullopt);
    ASSERT_FALSE(e.has_value()) << e->description;
    SPDLOG_INFO("Received data:\n{}", received_data);
}
