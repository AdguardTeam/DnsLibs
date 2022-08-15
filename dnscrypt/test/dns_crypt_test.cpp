#include <algorithm>
#include <chrono>
#include <magic_enum.hpp>
#include <sodium.h>

#include "common/defs.h"
#include "common/gtest_coro.h"
#include "common/logger.h"
#include "common/net_utils.h"
#include "common/time_utils.h"
#include "common/utils.h"
#include "dns/dnscrypt/dns_crypt_cipher.h"
#include "dns/dnscrypt/dns_crypt_client.h"
#include "dns/dnsstamp/dns_stamp.h"

#include "dns/dnscrypt/dns_crypt_ldns.h"

#ifdef _WIN32
#include <array>
#include <winsock2.h>
static const int ensure_sockets [[maybe_unused]] = WSAStartup(0x0202, std::array<WSADATA, 1>().data());
#endif

namespace ag::dns::dnscrypt::test {

TEST(DnscryptSodiumTest, SodiumInitialized) {
    // `1` means `already initialized`
    if (sodium_init() != 1) {
        FAIL();
    }
}

using ldns_rdf_ptr = UniquePtr<ldns_rdf, &ldns_rdf_free>;

static Logger logger{"dns_crypt_test"};

class DnscryptTest : public ::testing::Test {

    void SetUp() override {
        Logger::set_log_level(LOG_LEVEL_TRACE);
        m_loop->start();
    }

    void TearDown() override {
        m_loop->stop();
        m_loop->join();
    }

protected:
    EventLoopPtr m_loop = EventLoop::create();
    SocketFactory m_socket_factory = SocketFactory({*m_loop});
};

template <typename... Ts>
struct DnsCryptTestWithParam : DnscryptTest, ::testing::WithParamInterface<Ts...> {};

struct CipherTestData {
    dnscrypt::CryptoConstruction encryption_algorithm;
    Uint8Vector valid_cipher_text;
    dnscrypt::KeyArray valid_shared_key;
};

struct CipherTest : DnsCryptTestWithParam<CipherTestData> {};

static const CipherTestData cipher_test_data_values[]{
        {dnscrypt::CryptoConstruction::X_SALSA_20_POLY_1305,
                {139, 242, 162, 127, 140, 91, 194, 244, 122, 119, 21, 54, 123, 181, 235, 143, 173, 238, 20, 225, 93, 40,
                        236, 118, 44, 122},
                {88, 33, 20, 231, 222, 79, 169, 44, 137, 176, 138, 40, 176, 0, 214, 187, 82, 98, 99, 86, 30, 16, 48, 15,
                        42, 208, 235, 6, 131, 9, 118, 95}},
        {dnscrypt::CryptoConstruction::X_CHACHA_20_POLY_1305,
                {239, 152, 51, 4, 230, 57, 196, 97, 228, 162, 121, 34, 100, 81, 169, 123, 25, 0, 158, 102, 177, 198, 60,
                        174, 14, 125},
                {100, 100, 146, 92, 58, 10, 170, 0, 17, 33, 109, 34, 144, 43, 156, 88, 186, 251, 1, 50, 56, 177, 31, 86,
                        28, 240, 96, 67, 1, 152, 252, 86}},
};

static const auto cipher_key = [] {
    dnscrypt::KeyArray result;
    std::generate(result.begin(), result.end(), [n = 0]() mutable {
        return n++;
    });
    return result;
}();

static const auto cipher_nonce = [] {
    dnscrypt::nonce_array result;
    std::generate(result.begin(), result.end(), [n = result.size()]() mutable {
        return --n;
    });
    return result;
}();

static const auto cipher_src = [] {
    Uint8Array<10> result;
    result.fill(42);
    return result;
}();

TEST_P(CipherTest, Cipher) {
    const auto &[encryption_algorithm, valid_cipher_text, valid_shared_key] = GetParam();
    auto seal_res = dnscrypt::cipher_seal(
            encryption_algorithm, utils::make_string_view(cipher_src), cipher_nonce, cipher_key);
    ASSERT_FALSE(seal_res.has_error()) << "Seal error: " << seal_res.error()->str();
    auto &ciphertext = *seal_res;
    ASSERT_TRUE(std::equal(
            ciphertext.begin(), ciphertext.end(), std::begin(valid_cipher_text), std::end(valid_cipher_text)));
    auto open_res = dnscrypt::cipher_open(
            encryption_algorithm, utils::make_string_view(seal_res.value()), cipher_nonce, cipher_key);
    ASSERT_FALSE(open_res.has_error()) << "Open error: " << open_res.error()->str();
    auto &decrypted = *open_res;
    ASSERT_TRUE(std::equal(cipher_src.begin(), cipher_src.end(), decrypted.begin(), decrypted.end()))
            << "Src and decrypted not equal";
    ++ciphertext.front();
    auto bad_decrypted_res = dnscrypt::cipher_open(
            encryption_algorithm, utils::make_string_view(ciphertext), cipher_nonce, cipher_key);
    ASSERT_TRUE(bad_decrypted_res.has_error()) << "Tag validation failed";
    auto shared_key_res = dnscrypt::cipher_shared_key(encryption_algorithm, cipher_key, cipher_key);
    ASSERT_FALSE(shared_key_res.has_error()) << "Can not shared key: " << shared_key_res.error()->str();
    auto &shared_key = shared_key_res.value();
    ASSERT_TRUE(
            std::equal(shared_key.begin(), shared_key.end(), std::begin(valid_shared_key), std::end(valid_shared_key)));
}

INSTANTIATE_TEST_SUITE_P(CipherTestInstantiation, CipherTest, ::testing::ValuesIn(cipher_test_data_values));

using ParseStampTestDataType = std::tuple<const char *, void (*)(const char *, const ServerStamp &)>;

static void parse_stamp_test_data_log(const char *stamp_str, const ServerStamp &stamp) {
    infolog(logger, "{}", stamp_str);
    infolog(logger, "Protocol={}", stamp.proto);
    infolog(logger, "ProviderName={}", stamp.provider_name);
    infolog(logger, "Path={}", stamp.path);
}

static constexpr ParseStampTestDataType parse_stamp_test_data[]{
        {// Google DoH
                "sdns://AgUAAAAAAAAAAAAOZG5zLmdvb2dsZS5jb20NL2V4cGVyaW1lbnRhbA", parse_stamp_test_data_log},
        {// DoT 1.1.1.1
                "sdns://AwAAAAAAAAAAAAAHMS4xLjEuMQ", parse_stamp_test_data_log},
        {// AdGuard DNSCrypt
                "sdns://"
                "AQIAAAAAAAAAFDE3Ni4xMDMuMTMwLjEzMDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_"
                "OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20",
                [](const char *stamp_str, const ServerStamp &stamp) {
                    parse_stamp_test_data_log(stamp_str, stamp);
                    infolog(logger, "ServerAddrStr={}", stamp.server_addr_str);
                    infolog(logger, "ServerPk len={}\n", stamp.server_pk.size());
                }},
};

struct ParseStampTest : DnsCryptTestWithParam<ParseStampTestDataType> {
protected:
    SocketFactory m_socket_factory = SocketFactory({*m_loop});
};

TEST_P(ParseStampTest, parse_stamp) {
    const auto &stamp_str = std::get<0>(GetParam());
    const auto &log_f = std::get<1>(GetParam());
    auto stamp = ServerStamp::from_string(stamp_str);
    ASSERT_FALSE(stamp.has_error()) << stamp.error()->str();
    ASSERT_FALSE(stamp->provider_name.empty()) << "Empty provider name";
    log_f(stamp_str, *stamp);
}

INSTANTIATE_TEST_SUITE_P(ParseStampTestInstantiation, ParseStampTest, ::testing::ValuesIn(parse_stamp_test_data));

TEST_F(DnscryptTest, InvalidStamp) {
    dnscrypt::Client client;
    co_await m_loop->co_submit();
    auto err = (co_await client.dial(
            "sdns://AQIAAAAAAAAAFDE", *m_loop, dnscrypt::Client::DEFAULT_TIMEOUT, &m_socket_factory, {})).error();
    ASSERT_TRUE(err) << "Dial must not have been possible";
}

TEST_F(DnscryptTest, TimeoutOnDialError) {
    using namespace std::literals::chrono_literals;
    co_await m_loop->co_submit();
    // AdGuard DNS pointing to a wrong IP
    static constexpr auto stamp_str = "sdns://"
                                      "AQIAAAAAAAAADDguOC44Ljg6NTQ0MyDRK0fyUtzywrv4mRCG6vec5EldixbIoMQyLlLKPzkIcyIyLmRu"
                                      "c2NyeXB0LmRlZmF1bHQubnMxLmFkZ3VhcmQuY29t";
    dnscrypt::Client client;
    auto err = (co_await client.dial(stamp_str, *m_loop, 300ms, &m_socket_factory, {})).error();
    ASSERT_TRUE(err) << "Dial must not have been possible";
}

TEST_F(DnscryptTest, TimeoutOnDialExchange) {
    using namespace std::literals::chrono_literals;
    co_await m_loop->co_submit();
    // AdGuard DNS
    static constexpr auto stamp_str = "sdns://"
                                      "AQIAAAAAAAAAFDE3Ni4xMDMuMTMwLjEzMDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_"
                                      "OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20";
    dnscrypt::Client client;
    auto dial_res = co_await client.dial(stamp_str, *m_loop, 1000ms, &m_socket_factory, {});
    ASSERT_FALSE(dial_res.has_error()) << "Could not establish connection with " << stamp_str << " cause: " << dial_res.error()->str();
    auto &server_info = dial_res->server;
    // Point it to an IP where there's no DNSCrypt server
    server_info.set_server_address("8.8.8.8:5443");
    auto req = dnscrypt::create_request_ldns_pkt(LDNS_RR_TYPE_A, LDNS_RR_CLASS_IN, LDNS_RD,
            "google-public-dns-a.google.com.", dnscrypt::MAX_DNS_UDP_SAFE_PACKET_SIZE);
    ldns_pkt_set_random_id(req.get());
    auto exchange_err = (co_await client.exchange(*req, server_info, *m_loop, 1000ms, &m_socket_factory, {})).error();
    ASSERT_TRUE(exchange_err) << "Exchange must not have been possible";
}

static constexpr std::string_view check_dns_crypt_server_test_stamps[]{
        // AdGuard DNS
        "sdns://"
        "AQIAAAAAAAAAFDE3Ni4xMDMuMTMwLjEzMDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_"
        "OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20",
        // AdGuard DNS Family
        "sdns://"
        "AQIAAAAAAAAAFDE3Ni4xMDMuMTMwLjEzMjo1NDQzILgxXdexS27jIKRw3C7Wsao5jMnlhvhdRUXWuMm1AFq6ITIuZG5zY3J5cHQuZmFtaWx5Lm"
        "5zMS5hZGd1YXJkLmNvbQ",
};

static constexpr utils::TransportProtocol check_dns_crypt_server_test_protocols[]{
        utils::TransportProtocol::TP_UDP,
        utils::TransportProtocol::TP_TCP,
};

struct CheckDnscryptServerTest : DnsCryptTestWithParam<::testing::tuple<std::string_view, utils::TransportProtocol>> {
public:
    CheckDnscryptServerTest() {
        Logger::set_log_level(LogLevel::LOG_LEVEL_TRACE);
    }

protected:
    SocketFactory m_socket_factory = SocketFactory({*m_loop});
};

TEST_P(CheckDnscryptServerTest, CheckDnscryptServer) {
    using namespace std::literals::chrono_literals;
    co_await m_loop->co_submit();
    const auto &stamp_str = std::get<0>(GetParam());
    const auto &protocol = std::get<1>(GetParam());
    dnscrypt::Client client(protocol);
    auto dial_res = co_await client.dial(stamp_str, *m_loop, 10s, &m_socket_factory, {});
    ASSERT_FALSE(dial_res.has_error()) << "Could not establish connection with " << stamp_str << " cause: " << dial_res.error()->str();
    auto &[server_info, dial_rtt] = *dial_res;
    infolog(logger, "Established a connection with {}, ttl={}, rtt={}ms, protocol={}", server_info.get_provider_name(),
            format_gmtime(Secs(server_info.get_server_cert().not_after)), dial_rtt.count(),
            magic_enum::enum_name(protocol));
    auto req = dnscrypt::create_request_ldns_pkt(LDNS_RR_TYPE_A, LDNS_RR_CLASS_IN, LDNS_RD,
            "google-public-dns-a.google.com.",
            utils::make_optional_if(
                    protocol == utils::TransportProtocol::TP_UDP, dnscrypt::MAX_DNS_UDP_SAFE_PACKET_SIZE));
    ldns_pkt_set_random_id(req.get());
    auto exchange_res = co_await client.exchange(*req, server_info, *m_loop, 10s, &m_socket_factory, {});
    ASSERT_FALSE(exchange_res.has_error()) << "Couldn't talk to upstream " << server_info.get_provider_name() << ": "
                               << exchange_res.error()->str();
    auto &[reply, exchange_rtt] = *exchange_res;
    ldns_rr_list *reply_answer = ldns_pkt_answer(reply.get());
    size_t reply_answer_count = ldns_rr_list_rr_count(reply_answer);
    ASSERT_EQ(reply_answer_count, 1) << "DNS upstream " << server_info.get_provider_name()
                                     << " returned reply with wrong number of answers - " << reply_answer_count;
    ldns_rr *rr = ldns_rr_list_rr(reply_answer, 0);
    ASSERT_TRUE(rr);
    ldns_rdf *rdf = ldns_rr_rdf(rr, 0);
    ASSERT_TRUE(rdf);
    ldns_rdf_type rdf_type = ldns_rdf_get_type(rdf);
    ASSERT_EQ(rdf_type, LDNS_RDF_TYPE_A) << "DNS upstream " << server_info.get_provider_name()
                                         << " returned wrong answer type instead of A: " << rdf_type;
    auto rdf0 = ldns_rdf_ptr(ldns_rdf_new_frm_str(LDNS_RDF_TYPE_A, "8.8.8.8"));
    ASSERT_EQ(sizeof(in_addr), ldns_rdf_size(rdf));
    ASSERT_EQ(ldns_rdf_compare(rdf, rdf0.get()), 0)
            << "DNS upstream " << server_info.get_provider_name() << " returned wrong answer instead of 8.8.8.8: "
            << utils::addr_to_str({ldns_rdf_data(rdf), ldns_rdf_size(rdf)});
    infolog(logger, "Got proper response from {}, rtt={}ms, protocol={}", server_info.get_provider_name(),
            exchange_rtt.count(), magic_enum::enum_name(protocol));
    free(ldns_rdf_data(rdf0.get()));
}

INSTANTIATE_TEST_SUITE_P(CheckDnscryptServerTestInstantiation, CheckDnscryptServerTest,
        ::testing::Combine(::testing::ValuesIn(check_dns_crypt_server_test_stamps),
                ::testing::ValuesIn(check_dns_crypt_server_test_protocols)));

} // namespace ag::dnscrypt::test
