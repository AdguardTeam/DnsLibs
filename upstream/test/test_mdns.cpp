// Unit tests for the built-in mDNS client (RFC 6762) used to resolve `.local` names.
//
// The client sends one-shot QU queries to an ephemeral port and receives unicast responses;
// the loopback responder below stands in for a real mDNS responder, so the whole suite runs
// offline on every platform (the SystemUpstream integration itself is Android-only).

#include <algorithm>
#include <array>
#include <atomic>
#include <cstring>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include <ldns/ldns.h>

#include "common/gtest_coro.h"
#include "common/parallel.h"
#include "dns/common/event_loop.h"
#include "dns/net/socket.h"

#include "dns_test_helpers.h"
#include "loopback_dns_server.h"
#include "mdns_client.h"
#include "response_cache.h"

namespace ag::dns::upstream::test {

namespace {
constexpr uint16_t QUERY_ID = 0x1234;

ldns_pkt_ptr make_query(const char *name, ldns_rr_type type) {
    ldns_pkt *pkt = ldns_pkt_query_new(ldns_dname_new_frm_str(name), type, LDNS_RR_CLASS_IN, LDNS_RD);
    ldns_pkt_set_id(pkt, QUERY_ID);
    return ldns_pkt_ptr{pkt};
}

std::string describe_a_answer(const ldns_pkt &reply) {
    if (ldns_pkt_get_rcode(&reply) != LDNS_RCODE_NOERROR) {
        return "expected NOERROR rcode";
    }
    if (ldns_pkt_ancount(&reply) != 1u) {
        return "expected exactly one answer";
    }
    const ldns_rr *answer = ldns_rr_list_rr(ldns_pkt_answer(&reply), 0);
    if (answer == nullptr || ldns_rr_get_type(answer) != LDNS_RR_TYPE_A) {
        return "expected an A answer";
    }
    const ldns_rdf *rdf = ldns_rr_rdf(answer, 0);
    constexpr std::array<uint8_t, 4> expected{1, 2, 3, 4};
    if (rdf == nullptr || ldns_rdf_size(rdf) != expected.size()
            || std::memcmp(ldns_rdf_data(rdf), expected.data(), expected.size()) != 0) {
        return "answer data is not 1.2.3.4";
    }
    return {};
}

// A minimal IPv6-only loopback DNS responder (the shared LoopbackDnsServer binds IPv4 only).
class LoopbackDns6Server {
public:
    using Handler = ag::test::detail::DnsReplyHandler;

    explicit LoopbackDns6Server(Handler handler)
            : m_handler(std::move(handler)) {
    }

    ~LoopbackDns6Server() {
        stop();
    }

    LoopbackDns6Server(const LoopbackDns6Server &) = delete;
    LoopbackDns6Server &operator=(const LoopbackDns6Server &) = delete;

    bool start() {
        ag::test::detail::ensure_winsock();
        m_socket = ag::test::detail::open_dgram_socket6();
        if (m_socket == ag::test::detail::invalid_socket()) {
            return false;
        }

        sockaddr_in6 addr{};
        addr.sin6_family = AF_INET6;
        addr.sin6_addr = in6addr_loopback;
        addr.sin6_port = 0;
        if (0 != ::bind(m_socket, reinterpret_cast<sockaddr *>(&addr), sizeof(addr))) {
            ag::test::detail::close_fd(m_socket);
            m_socket = ag::test::detail::invalid_socket();
            return false;
        }

        ag::test::detail::socklen_type len = sizeof(addr);
        if (0 != ::getsockname(m_socket, reinterpret_cast<sockaddr *>(&addr), &len)) {
            ag::test::detail::close_fd(m_socket);
            m_socket = ag::test::detail::invalid_socket();
            return false;
        }
        m_port = ntohs(addr.sin6_port);

        m_running.store(true);
        m_thread = std::thread([this] {
            loop();
        });
        return true;
    }

    void stop() {
        if (!m_running.exchange(false)) {
            return;
        }
        ag::test::detail::shutdown_socket(m_socket);
        ag::test::detail::close_fd(m_socket);
        m_socket = ag::test::detail::invalid_socket();
        if (m_thread.joinable()) {
            m_thread.join();
        }
    }

    uint16_t port() const {
        return m_port;
    }

private:
    void loop() {
        std::vector<uint8_t> buffer(ag::test::detail::MAX_DNS_PACKET);
        while (m_running.load()) {
            sockaddr_in6 client{};
            ag::test::detail::socklen_type client_len = sizeof(client);
#ifdef _WIN32
            int n = ::recvfrom(m_socket, reinterpret_cast<char *>(buffer.data()), static_cast<int>(buffer.size()), 0,
                    reinterpret_cast<sockaddr *>(&client), &client_len);
#else
            ssize_t n = ::recvfrom(
                    m_socket, buffer.data(), buffer.size(), 0, reinterpret_cast<sockaddr *>(&client), &client_len);
#endif
            if (n <= 0) {
                break;
            }

            ldns_pkt *request_raw = nullptr;
            if (ldns_wire2pkt(&request_raw, buffer.data(), static_cast<size_t>(n)) != LDNS_STATUS_OK
                    || request_raw == nullptr) {
                continue;
            }
            ldns_pkt_ptr request{request_raw};
            ldns_pkt_ptr reply = m_handler(*request);
            if (!reply) {
                continue;
            }

            ldns_buffer_ptr out{ldns_buffer_new(ag::test::detail::MAX_DNS_PACKET)};
            if (!out || ldns_pkt2buffer_wire(out.get(), reply.get()) != LDNS_STATUS_OK) {
                continue;
            }
#ifdef _WIN32
            (void) ::sendto(m_socket, reinterpret_cast<const char *>(ldns_buffer_begin(out.get())),
                    static_cast<int>(ldns_buffer_position(out.get())), 0, reinterpret_cast<sockaddr *>(&client),
                    client_len);
#else
            (void) ::sendto(m_socket, ldns_buffer_begin(out.get()), ldns_buffer_position(out.get()), 0,
                    reinterpret_cast<sockaddr *>(&client), client_len);
#endif
        }
    }

    Handler m_handler;
    uint16_t m_port{0};
    std::atomic_bool m_running{false};
    ag::test::detail::socket_type m_socket{ag::test::detail::invalid_socket()};
    std::thread m_thread;
};

// Returns a currently free loopback UDP port (used as the mDNS listener port in tests).
uint16_t pick_free_udp_port() {
    ag::test::detail::socket_type s = ag::test::detail::open_dgram_socket();
    if (s == ag::test::detail::invalid_socket()) {
        return 0;
    }
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    ag::test::detail::socklen_type len = sizeof(addr);
    if (0 != ::bind(s, reinterpret_cast<sockaddr *>(&addr), sizeof(addr))
            || 0 != ::getsockname(s, reinterpret_cast<sockaddr *>(&addr), &len)) {
        ag::test::detail::close_fd(s);
        return 0;
    }
    uint16_t port = ntohs(addr.sin_port);
    ag::test::detail::close_fd(s);
    return port;
}

// Sends `payload` to 127.0.0.1:`port` (emulates a multicast response arriving at the listener).
void send_udp_to_loopback(const std::vector<uint8_t> &payload, uint16_t port) {
    ag::test::detail::ensure_winsock();
    ag::test::detail::socket_type s = ag::test::detail::open_dgram_socket();
    if (s == ag::test::detail::invalid_socket()) {
        return;
    }
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);
#ifdef _WIN32
    (void) ::sendto(s, reinterpret_cast<const char *>(payload.data()), static_cast<int>(payload.size()), 0,
            reinterpret_cast<sockaddr *>(&addr), sizeof(addr));
#else
    (void) ::sendto(s, payload.data(), payload.size(), 0, reinterpret_cast<sockaddr *>(&addr), sizeof(addr));
#endif
    ag::test::detail::close_fd(s);
}

// Builds a canned NOERROR/A reply for `name`.
ldns_pkt_ptr make_canned_reply(const char *name) {
    ldns_pkt *reply = ldns_pkt_query_new(ldns_dname_new_frm_str(name), LDNS_RR_TYPE_A, LDNS_RR_CLASS_IN, LDNS_RD);
    ldns_pkt_set_id(reply, QUERY_ID);
    ldns_pkt_set_qr(reply, true);
    ldns_pkt_set_ra(reply, true);
    const ldns_rr *question = ldns_rr_list_rr(ldns_pkt_question(reply), 0);
    ag::test::add_a_answer(reply, question);
    return ldns_pkt_ptr{reply};
}

// Serializes a DNS packet to wire format.
std::vector<uint8_t> serialize_packet(const ldns_pkt *pkt) {
    ldns_buffer_ptr buffer{ldns_buffer_new(ag::test::detail::MAX_DNS_PACKET)};
    if (!buffer || ldns_pkt2buffer_wire(buffer.get(), pkt) != LDNS_STATUS_OK) {
        return {};
    }
    return {ldns_buffer_begin(buffer.get()), ldns_buffer_begin(buffer.get()) + ldns_buffer_position(buffer.get())};
}
} // namespace

class MdnsClientTest : public ::testing::Test {
protected:
    void SetUp() override {
        m_loop = EventLoop::create();
        m_loop->start();
        m_socket_factory = std::make_unique<SocketFactory>(SocketFactory::Parameters{.loop = *m_loop});
    }

    void TearDown() override {
        m_socket_factory.reset();
        m_loop->stop();
        m_loop->join();
    }

    std::unique_ptr<MdnsClient> make_client(const ag::test::LoopbackDnsServer &server, Millis timeout) {
        return MdnsClient::create(MdnsClient::Config{
                .loop = m_loop.get(),
                .socket_factory = m_socket_factory.get(),
                .timeout = timeout,
                .servers = {SocketAddress("127.0.0.1", server.port())},
        });
    }

    EventLoopPtr m_loop;
    std::unique_ptr<SocketFactory> m_socket_factory;
};

TEST_F(MdnsClientTest, DetectsLocalNames) {
    EXPECT_TRUE(MdnsClient::is_local_name("foo.local"));
    EXPECT_TRUE(MdnsClient::is_local_name("foo.local."));
    EXPECT_TRUE(MdnsClient::is_local_name("_http._tcp.local."));
    EXPECT_TRUE(MdnsClient::is_local_name("LOCAL"));
    EXPECT_TRUE(MdnsClient::is_local_name("local."));
    EXPECT_FALSE(MdnsClient::is_local_name("localdomain"));
    EXPECT_FALSE(MdnsClient::is_local_name("example.com."));
    EXPECT_FALSE(MdnsClient::is_local_name(""));
    co_return;
}

TEST_F(MdnsClientTest, ResolvesARecord) {
    co_await m_loop->co_submit();

    std::atomic<bool> qu_bit_seen{false};
    std::atomic<bool> zero_id_seen{false};
    ag::test::LoopbackDnsServer server(
            [&qu_bit_seen, &zero_id_seen](const ldns_pkt &request) {
                const ldns_rr *question = ldns_rr_list_rr(ldns_pkt_question(&request), 0);
                if (question != nullptr) {
                    qu_bit_seen.store((ldns_rr_get_class(question) & 0x8000) != 0);
                }
                zero_id_seen.store(ldns_pkt_id(&request) == 0);
                ldns_pkt_ptr reply = ag::test::make_base_reply(request);
                ag::test::add_a_answer(reply.get(), question);
                return reply;
            },
            /*tcp=*/false);
    server.start();
    auto client = make_client(server, Millis{1000});

    ldns_pkt_ptr req = make_query("foo.local.", LDNS_RR_TYPE_A);
    auto res = co_await client->exchange(req.get());
    ASSERT_FALSE(res.has_error()) << res.error()->str();

    const ldns_pkt &reply = *res.value();
    EXPECT_EQ(ldns_pkt_id(&reply), QUERY_ID);
    EXPECT_EQ(ldns_pkt_qdcount(&reply), 1u);
    EXPECT_TRUE(ldns_pkt_qr(&reply));
    EXPECT_FALSE(ldns_pkt_tc(&reply));
    std::string answer_error = describe_a_answer(reply);
    ASSERT_TRUE(answer_error.empty()) << answer_error;
    EXPECT_EQ(ldns_rr_ttl(ldns_rr_list_rr(ldns_pkt_answer(&reply), 0)), 300u);

    // The outgoing query must be a one-shot QU query with the mDNS zero ID.
    EXPECT_TRUE(qu_bit_seen.load());
    EXPECT_TRUE(zero_id_seen.load());

    server.stop();
}

TEST_F(MdnsClientTest, ResolvesAaaaRecordOverIpv6) {
    co_await m_loop->co_submit();

    LoopbackDns6Server server([](const ldns_pkt &request) {
        ldns_pkt_ptr reply = ag::test::make_base_reply(request);
        const ldns_rr *question = ldns_rr_list_rr(ldns_pkt_question(&request), 0);
        if (question == nullptr) {
            return ldns_pkt_ptr{};
        }
        ldns_rr *answer = ldns_rr_new();
        ldns_rr_set_owner(answer, ldns_rdf_clone(ldns_rr_owner(question)));
        ldns_rr_set_ttl(answer, 120);
        ldns_rr_set_type(answer, LDNS_RR_TYPE_AAAA);
        ldns_rr_set_class(answer, LDNS_RR_CLASS_IN);
        ldns_rr_push_rdf(answer, ldns_rdf_new_frm_str(LDNS_RDF_TYPE_AAAA, "2001:db8::1"));
        ldns_pkt_push_rr(reply.get(), LDNS_SECTION_ANSWER, answer);
        return reply;
    });
    if (!server.start()) {
        GTEST_SKIP() << "IPv6 is not available on this host";
    }

    // IPv6 transport is opt-in, so the test enables it explicitly.
    auto client = MdnsClient::create(MdnsClient::Config{
            .loop = m_loop.get(),
            .socket_factory = m_socket_factory.get(),
            .timeout = Millis{1000},
            .servers = {SocketAddress("::1", server.port())},
            .enable_ipv6 = true,
    });

    ldns_pkt_ptr req = make_query("foo.local.", LDNS_RR_TYPE_AAAA);
    auto res = co_await client->exchange(req.get());
    ASSERT_FALSE(res.has_error()) << res.error()->str();

    const ldns_pkt &reply = *res.value();
    EXPECT_EQ(ldns_pkt_get_rcode(&reply), LDNS_RCODE_NOERROR);
    ASSERT_EQ(ldns_pkt_ancount(&reply), 1u);
    const ldns_rr *answer = ldns_rr_list_rr(ldns_pkt_answer(&reply), 0);
    ASSERT_NE(answer, nullptr);
    EXPECT_EQ(ldns_rr_get_type(answer), LDNS_RR_TYPE_AAAA);
    EXPECT_EQ(ldns_rr_ttl(answer), 120u);

    server.stop();
}

TEST_F(MdnsClientTest, ResolvesCnameAlias) {
    co_await m_loop->co_submit();

    ag::test::LoopbackDnsServer server(
            [](const ldns_pkt &request) {
                ldns_pkt_ptr reply = ag::test::make_base_reply(request);
                // A two-hop alias chain: every record belongs to the answer section.
                ag::test::add_rr_from_str(reply.get(), "alias.local. 120 IN CNAME mid.local.");
                ag::test::add_rr_from_str(reply.get(), "mid.local. 120 IN CNAME host.local.");
                ag::test::add_rr_from_str(reply.get(), "host.local. 120 IN A 1.2.3.4");
                return reply;
            },
            /*tcp=*/false);
    server.start();
    auto client = make_client(server, Millis{1000});

    ldns_pkt_ptr req = make_query("alias.local.", LDNS_RR_TYPE_A);
    auto res = co_await client->exchange(req.get());
    ASSERT_FALSE(res.has_error()) << res.error()->str();

    const ldns_pkt &reply = *res.value();
    EXPECT_EQ(ldns_pkt_get_rcode(&reply), LDNS_RCODE_NOERROR);
    ASSERT_EQ(ldns_pkt_ancount(&reply), 3u);
    EXPECT_EQ(ldns_rr_get_type(ldns_rr_list_rr(ldns_pkt_answer(&reply), 0)), LDNS_RR_TYPE_CNAME);
    EXPECT_EQ(ldns_rr_get_type(ldns_rr_list_rr(ldns_pkt_answer(&reply), 1)), LDNS_RR_TYPE_CNAME);
    const ldns_rr *answer = ldns_rr_list_rr(ldns_pkt_answer(&reply), 2);
    EXPECT_EQ(ldns_rr_get_type(answer), LDNS_RR_TYPE_A);
    EXPECT_EQ(ldns_rr_ttl(answer), 120u);

    server.stop();
}

TEST_F(MdnsClientTest, HandlesNsecNegativeResponse) {
    co_await m_loop->co_submit();

    ag::test::LoopbackDnsServer server(
            [](const ldns_pkt &request) {
                ldns_pkt_ptr reply = ag::test::make_base_reply(request);
                ag::test::add_rr_from_str(reply.get(), "foo.local. 120 IN NSEC foo.local. A");
                return reply;
            },
            /*tcp=*/false);
    server.start();
    auto client = make_client(server, Millis{1000});

    ldns_pkt_ptr req = make_query("foo.local.", LDNS_RR_TYPE_AAAA);
    auto res = co_await client->exchange(req.get());
    ASSERT_FALSE(res.has_error()) << res.error()->str();

    const ldns_pkt &reply = *res.value();
    // A negative mDNS answer is NOERROR with an NSEC record (RFC 6762 §6.1), not NXDOMAIN.
    EXPECT_EQ(ldns_pkt_get_rcode(&reply), LDNS_RCODE_NOERROR);
    ASSERT_EQ(ldns_pkt_ancount(&reply), 1u);
    EXPECT_EQ(ldns_rr_get_type(ldns_rr_list_rr(ldns_pkt_answer(&reply), 0)), LDNS_RR_TYPE_NSEC);

    server.stop();
}

TEST_F(MdnsClientTest, ClearsUnicastResponseBitOnRetransmit) {
    co_await m_loop->co_submit();

    std::atomic<int> query_count{0};
    std::atomic<bool> first_qu{false};
    std::atomic<bool> second_qu{true};
    ag::test::LoopbackDnsServer server(
            [&query_count, &first_qu, &second_qu](const ldns_pkt &request) {
                const ldns_rr *question = ldns_rr_list_rr(ldns_pkt_question(&request), 0);
                const bool qu = question != nullptr && (ldns_rr_get_class(question) & 0x8000) != 0;
                const int n = query_count.fetch_add(1);
                if (n == 0) {
                    first_qu.store(qu);
                    return ldns_pkt_ptr{}; // drop the first query to force a retransmit
                }
                if (n == 1) {
                    second_qu.store(qu);
                }
                ldns_pkt_ptr reply = ag::test::make_base_reply(request);
                ag::test::add_a_answer(reply.get(), question);
                return reply;
            },
            /*tcp=*/false);
    server.start();
    auto client = make_client(server, Millis{1500});

    ldns_pkt_ptr req = make_query("foo.local.", LDNS_RR_TYPE_A);
    auto res = co_await client->exchange(req.get());
    ASSERT_FALSE(res.has_error()) << res.error()->str();

    EXPECT_EQ(query_count.load(), 2);
    EXPECT_TRUE(first_qu.load());
    EXPECT_FALSE(second_qu.load());

    server.stop();
}

TEST_F(MdnsClientTest, ReceivesResponseOnMulticastListener) {
    co_await m_loop->co_submit();

    const uint16_t listener_port = pick_free_udp_port();
    ASSERT_NE(listener_port, 0);

    auto client = MdnsClient::create(MdnsClient::Config{
            .loop = m_loop.get(),
            .socket_factory = m_socket_factory.get(),
            .timeout = Millis{1000},
            .multicast_port = listener_port,
    });

    // Emulate a responder that multicasts its answer: the reply is delivered to the client's
    // listener socket (bound to the mDNS port) rather than to the query socket.
    std::vector<uint8_t> payload = serialize_packet(make_canned_reply("foo.local.").get());
    ASSERT_FALSE(payload.empty());
    m_loop->schedule(Micros{100000}, [payload = std::move(payload), listener_port] {
        send_udp_to_loopback(payload, listener_port);
    });

    ldns_pkt_ptr req = make_query("foo.local.", LDNS_RR_TYPE_A);
    auto res = co_await client->exchange(req.get());
    ASSERT_FALSE(res.has_error()) << res.error()->str();

    std::string answer_error = describe_a_answer(*res.value());
    ASSERT_TRUE(answer_error.empty()) << answer_error;
}

TEST_F(MdnsClientTest, SplitsAdditionalRecords) {
    co_await m_loop->co_submit();

    ag::test::LoopbackDnsServer server(
            [](const ldns_pkt &request) {
                ldns_pkt_ptr reply = ag::test::make_base_reply(request);
                const ldns_rr *question = ldns_rr_list_rr(ldns_pkt_question(&request), 0);
                ag::test::add_a_answer(reply.get(), question);
                ag::test::add_rr_from_str(reply.get(), "foo.local. 120 IN AAAA 2001:db8::1");
                return reply;
            },
            /*tcp=*/false);
    server.start();
    auto client = make_client(server, Millis{1000});

    ldns_pkt_ptr req = make_query("foo.local.", LDNS_RR_TYPE_A);
    auto res = co_await client->exchange(req.get());
    ASSERT_FALSE(res.has_error()) << res.error()->str();

    const ldns_pkt &reply = *res.value();
    ASSERT_EQ(ldns_pkt_ancount(&reply), 1u);
    ASSERT_EQ(ldns_pkt_arcount(&reply), 1u);
    EXPECT_EQ(ldns_rr_get_type(ldns_rr_list_rr(ldns_pkt_answer(&reply), 0)), LDNS_RR_TYPE_A);
    EXPECT_EQ(ldns_rr_get_type(ldns_rr_list_rr(ldns_pkt_additional(&reply), 0)), LDNS_RR_TYPE_AAAA);

    server.stop();
}

TEST_F(MdnsClientTest, ReturnsNxdomainWhenNoResponderAnswers) {
    co_await m_loop->co_submit();

    ag::test::LoopbackDnsServer server(
            [](const ldns_pkt &) {
                return ldns_pkt_ptr{};
            },
            /*tcp=*/false);
    server.start();
    auto client = make_client(server, Millis{200});

    ldns_pkt_ptr req = make_query("missing.local.", LDNS_RR_TYPE_A);
    auto res = co_await client->exchange(req.get());
    ASSERT_FALSE(res.has_error()) << res.error()->str();

    const ldns_pkt &reply = *res.value();
    EXPECT_EQ(ldns_pkt_get_rcode(&reply), LDNS_RCODE_NXDOMAIN);
    ASSERT_EQ(ldns_pkt_nscount(&reply), 1u);
    const ldns_rr *soa = ldns_rr_list_rr(ldns_pkt_authority(&reply), 0);
    ASSERT_NE(soa, nullptr);
    EXPECT_EQ(ldns_rr_get_type(soa), LDNS_RR_TYPE_SOA);

    server.stop();
}

TEST_F(MdnsClientTest, ReplyIsAcceptedByProxyResponseCache) {
    co_await m_loop->co_submit();

    ag::test::LoopbackDnsServer server(
            [](const ldns_pkt &request) {
                ldns_pkt_ptr reply = ag::test::make_base_reply(request);
                const ldns_rr *question = ldns_rr_list_rr(ldns_pkt_question(&request), 0);
                ag::test::add_a_answer(reply.get(), question);
                return reply;
            },
            /*tcp=*/false);
    server.start();
    auto client = make_client(server, Millis{1000});

    ldns_pkt_ptr req = make_query("foo.local.", LDNS_RR_TYPE_A);
    auto res = co_await client->exchange(req.get());
    ASSERT_FALSE(res.has_error()) << res.error()->str();

    // The mDNS reply is a regular upstream reply, so the proxy response cache must accept
    // and serve it with its TTL: this is what turns repeated `.local` queries into cache hits
    // instead of repeated multicast queries.
    ResponseCache cache(10);
    cache.put(req.get(), ldns_pkt_ptr{ldns_pkt_clone(res.value().get())}, std::nullopt);
    ResponseCache::Result cached = cache.get(req.get());
    ASSERT_NE(cached.response, nullptr);
    EXPECT_FALSE(cached.expired);
    EXPECT_EQ(ldns_pkt_get_rcode(cached.response.get()), LDNS_RCODE_NOERROR);
    ASSERT_EQ(ldns_pkt_ancount(cached.response.get()), 1u);
    EXPECT_EQ(ldns_rr_get_type(ldns_rr_list_rr(ldns_pkt_answer(cached.response.get()), 0)), LDNS_RR_TYPE_A);

    server.stop();
}

TEST_F(MdnsClientTest, IgnoresResponsesForOtherNames) {
    co_await m_loop->co_submit();

    ag::test::LoopbackDnsServer server(
            [](const ldns_pkt &request) {
                ldns_pkt_ptr reply = ag::test::make_base_reply(request);
                ag::test::add_rr_from_str(reply.get(), "other.local. 120 IN A 5.6.7.8");
                return reply;
            },
            /*tcp=*/false);
    server.start();
    auto client = make_client(server, Millis{200});

    ldns_pkt_ptr req = make_query("foo.local.", LDNS_RR_TYPE_A);
    auto res = co_await client->exchange(req.get());
    ASSERT_FALSE(res.has_error()) << res.error()->str();
    EXPECT_EQ(ldns_pkt_get_rcode(res.value().get()), LDNS_RCODE_NXDOMAIN);

    server.stop();
}

TEST_F(MdnsClientTest, HandlesConcurrentRequests) {
    co_await m_loop->co_submit();

    ag::test::LoopbackDnsServer server(
            [](const ldns_pkt &request) {
                ldns_pkt_ptr reply = ag::test::make_base_reply(request);
                const ldns_rr *question = ldns_rr_list_rr(ldns_pkt_question(&request), 0);
                if (question == nullptr) {
                    return ldns_pkt_ptr{};
                }
                ag::test::add_a_answer(reply.get(), question);
                return reply;
            },
            /*tcp=*/false);
    server.start();
    auto client = make_client(server, Millis{1000});

    ldns_pkt_ptr req1 = make_query("one.local.", LDNS_RR_TYPE_A);
    ldns_pkt_ptr req2 = make_query("two.local.", LDNS_RR_TYPE_A);
    auto results = co_await parallel::all_of<Result<ldns_pkt_ptr, DnsError>>(
            client->exchange(req1.get()), client->exchange(req2.get()));

    // Both in-flight requests must be matched to their own response.
    ASSERT_EQ(results.size(), 2u);
    std::vector<std::string> answered_names;
    for (auto &result : results) {
        ASSERT_FALSE(result.has_error()) << result.error()->str();
        EXPECT_EQ(ldns_pkt_get_rcode(result.value().get()), LDNS_RCODE_NOERROR);
        ASSERT_EQ(ldns_pkt_ancount(result.value().get()), 1u);
        AllocatedPtr<char> owner{
                ldns_rdf2str(ldns_rr_owner(ldns_rr_list_rr(ldns_pkt_answer(result.value().get()), 0)))};
        answered_names.emplace_back(owner != nullptr ? owner.get() : "");
    }
    std::sort(answered_names.begin(), answered_names.end());
    EXPECT_EQ(answered_names, (std::vector<std::string>{"one.local.", "two.local."}));

    server.stop();
}

TEST_F(MdnsClientTest, ShutdownWithPendingRequest) {
    co_await m_loop->co_submit();

    ag::test::LoopbackDnsServer server(
            [](const ldns_pkt &) {
                return ldns_pkt_ptr{}; // never answer, keep the request pending
            },
            /*tcp=*/false);
    server.start();
    auto client = make_client(server, Millis{5000});
    ldns_pkt_ptr req = make_query("foo.local.", LDNS_RR_TYPE_A);

    std::optional<DnsError> result;
    coro::run_detached([](MdnsClient *client, ldns_pkt *request, std::optional<DnsError> *out) -> coro::Task<void> {
        auto res = co_await client->exchange(request);
        if (res.has_error()) {
            *out = res.error()->value();
        }
    }(client.get(), req.get(), &result));

    // Destroying the client must resume the pending request with AE_SHUTTING_DOWN.
    client.reset();
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, DnsError::AE_SHUTTING_DOWN);

    server.stop();
}

} // namespace ag::dns::upstream::test
