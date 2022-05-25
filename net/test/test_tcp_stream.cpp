#include <gtest/gtest.h>

#include "common/logger.h"
#include "net/blocking_socket.h"
#include "net/socket.h"

namespace ag::test {

static Logger logger{"test_tcp_stream"};

TEST(TcpStream, DISABLED_Blocking) {
    SocketFactory factory({});
    BlockingSocket socket(factory.make_socket({utils::TP_TCP}));
    ASSERT_TRUE(socket);

    auto e = socket.connect({SocketAddress("1.1.1.1", 80), Secs(1)});
    ASSERT_FALSE(e.has_value()) << e->description;

    std::string_view GET = "GET / HTTP/1.1\r\nHost: 1.1.1.1\r\n\r\n";
    e = socket.send({(uint8_t *) GET.data(), GET.size()});
    ASSERT_FALSE(e.has_value()) << e->description;

    std::string received_data;
    e = socket.receive(
            {
                    [](void *arg, Uint8View data) {
                        *(std::string *) arg = {(char *) data.data(), data.size()};
                        return false;
                    },
                    &received_data,
            },
            std::nullopt);
    ASSERT_FALSE(e.has_value()) << e->description;
    infolog(logger, "Received data:\n{}", received_data);
}

TEST(TcpStream, DISABLED_HttpProxy) {
    Logger::set_log_level(LogLevel::LOG_LEVEL_TRACE);

    OutboundProxySettings proxy_settings = {OutboundProxyProtocol::HTTP_CONNECT, "127.0.0.1", 3129};
    SocketFactory factory({&proxy_settings});
    BlockingSocket socket(factory.make_socket({utils::TP_TCP}));
    ASSERT_TRUE(socket);

    auto e = socket.connect({SocketAddress("1.1.1.1", 80), Secs(1)});
    ASSERT_FALSE(e.has_value()) << e->description;

    std::string_view GET = "GET / HTTP/1.1\r\nHost: 1.1.1.1\r\n\r\n";
    e = socket.send({(uint8_t *) GET.data(), GET.size()});
    ASSERT_FALSE(e.has_value()) << e->description;

    std::string received_data;
    e = socket.receive(
            {
                    [](void *arg, Uint8View data) {
                        *(std::string *) arg = {(char *) data.data(), data.size()};
                        return false;
                    },
                    &received_data,
            },
            std::nullopt);
    ASSERT_FALSE(e.has_value()) << e->description;
    infolog(logger, "Received data:\n{}", received_data);
}

TEST(TcpStream, DISABLED_SocksProxy) {
    Logger::set_log_level(LogLevel::LOG_LEVEL_TRACE);

    OutboundProxySettings proxy_settings = {OutboundProxyProtocol::SOCKS5, "127.0.0.1", 8888};
    SocketFactory factory({&proxy_settings});
    BlockingSocket socket(factory.make_socket({utils::TP_TCP}));
    ASSERT_TRUE(socket);

    auto e = socket.connect({SocketAddress("1.1.1.1", 80), Secs(1)});
    ASSERT_FALSE(e.has_value()) << e->description;

    std::string_view GET = "GET / HTTP/1.1\r\nHost: 1.1.1.1\r\n\r\n";
    e = socket.send({(uint8_t *) GET.data(), GET.size()});
    ASSERT_FALSE(e.has_value()) << e->description;

    std::string received_data;
    e = socket.receive(
            {
                    [](void *arg, Uint8View data) {
                        *(std::string *) arg = {(char *) data.data(), data.size()};
                        return false;
                    },
                    &received_data,
            },
            std::nullopt);
    ASSERT_FALSE(e.has_value()) << e->description;
    infolog(logger, "Received data:\n{}", received_data);
}

} // namespace ag::test
