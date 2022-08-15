#include "common/gtest_coro.h"

#include "common/logger.h"
#include "dns/net/aio_socket.h"
#include "dns/net/socket.h"

namespace ag::dns::test {

static Logger logger{"test_tcp_stream"};

class TcpStreamTest : public ::testing::Test {
protected:
    void SetUp() override {
        m_loop = EventLoop::create();
        m_loop->start();
    }

    void TearDown() override {
        m_loop->stop();
        m_loop->join();
    };

    EventLoopPtr m_loop;
};

TEST_F(TcpStreamTest, DISABLED_Blocking) {
    Logger::set_log_level(LOG_LEVEL_TRACE);
    co_await m_loop->co_submit();
    SocketFactory factory({*m_loop});
    AioSocket socket(factory.make_socket({utils::TP_TCP}));

    auto e = co_await socket.connect({m_loop.get(), SocketAddress("1.1.1.1", 80), Secs(1)});
    ASSERT_FALSE(e) << e->str();

    std::string_view GET = "GET / HTTP/1.1\r\nHost: 1.1.1.1\r\n\r\n";
    e = socket.send({(uint8_t *) GET.data(), GET.size()});
    ASSERT_FALSE(e) << e->str();

    std::string received_data;
    e = co_await socket.receive(
            {
                    [](void *arg, Uint8View data) {
                        *(std::string *) arg = {(char *) data.data(), data.size()};
                        return false;
                    },
                    &received_data,
            },
            std::nullopt);
    ASSERT_FALSE(e) << e->str();
    infolog(logger, "Received data:\n{}", received_data);
}

TEST_F(TcpStreamTest, DISABLED_HttpProxy) {
    co_await m_loop->co_submit();
    Logger::set_log_level(LogLevel::LOG_LEVEL_TRACE);

    OutboundProxySettings proxy_settings = {OutboundProxyProtocol::HTTP_CONNECT, "127.0.0.1", 3129};
    SocketFactory factory({*m_loop, &proxy_settings});
    AioSocket socket(factory.make_socket({utils::TP_TCP}));

    auto e = co_await socket.connect({m_loop.get(), SocketAddress("1.1.1.1", 80), Secs(1)});
    ASSERT_FALSE(e) << e->str();

    std::string_view GET = "GET / HTTP/1.1\r\nHost: 1.1.1.1\r\n\r\n";
    e = socket.send({(uint8_t *) GET.data(), GET.size()});
    ASSERT_FALSE(e) << e->str();

    std::string received_data;
    e = co_await socket.receive(
            {
                    [](void *arg, Uint8View data) {
                        *(std::string *) arg = {(char *) data.data(), data.size()};
                        return false;
                    },
                    &received_data,
            },
            std::nullopt);
    ASSERT_FALSE(e) << e->str();
    infolog(logger, "Received data:\n{}", received_data);
}

TEST_F(TcpStreamTest, DISABLED_SocksProxy) {
    co_await m_loop->co_submit();
    Logger::set_log_level(LogLevel::LOG_LEVEL_TRACE);

    OutboundProxySettings proxy_settings = {OutboundProxyProtocol::SOCKS5, "127.0.0.1", 8888};
    SocketFactory factory({*m_loop, &proxy_settings});
    AioSocket socket(factory.make_socket({utils::TP_TCP}));

    auto e = co_await socket.connect({m_loop.get(), SocketAddress("1.1.1.1", 80), Secs(1)});
    ASSERT_FALSE(e) << e->str();

    std::string_view GET = "GET / HTTP/1.1\r\nHost: 1.1.1.1\r\n\r\n";
    e = socket.send({(uint8_t *) GET.data(), GET.size()});
    ASSERT_FALSE(e) << e->str();

    std::string received_data;
    e = co_await socket.receive(
            {
                    [](void *arg, Uint8View data) {
                        *(std::string *) arg = {(char *) data.data(), data.size()};
                        return false;
                    },
                    &received_data,
            },
            std::nullopt);
    ASSERT_FALSE(e) << e->str();
    infolog(logger, "Received data:\n{}", received_data);
}

} // namespace ag::dns::test
