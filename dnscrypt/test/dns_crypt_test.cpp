#include <gtest/gtest.h>
#include <dns_crypt_client.h>
#include <algorithm>
#include <chrono>
#include <arpa/inet.h>
#include <sodium.h>
#include <spdlog/spdlog.h>
#include <ag_utils.h>
#include <dns_crypt_cipher.h>
#include <dns_crypt_ldns.h>
#include <dns_stamp.h>

class dnscrypt_test : public ::testing::Test {
    void SetUp() override {
        if (sodium_init() == -1) {
            FAIL();
        }
    }
};

template<typename... Ts>
struct dnscrypt_test_with_param : dnscrypt_test, ::testing::WithParamInterface<Ts...> {};

struct cipher_test_data {
    ag::dnscrypt::crypto_construction encryption_algorithm;
    ag::uint8_vector valid_cipher_text;
    ag::dnscrypt::key_array valid_shared_key;
};

struct cipher_test : dnscrypt_test_with_param<cipher_test_data> {};

static const cipher_test_data cipher_test_data_values[]{
    {
        ag::dnscrypt::crypto_construction::X_SALSA_20_POLY_1305,
        {139, 242, 162, 127, 140, 91, 194, 244, 122, 119, 21, 54, 123, 181, 235, 143, 173, 238, 20, 225, 93, 40, 236, 118, 44, 122},
        {88, 33, 20, 231, 222, 79, 169, 44, 137, 176, 138, 40, 176, 0, 214, 187, 82, 98, 99, 86, 30, 16, 48, 15, 42, 208, 235, 6, 131, 9, 118, 95}
    },
    {
        ag::dnscrypt::crypto_construction::X_CHACHA_20_POLY_1305,
        {239, 152, 51, 4, 230, 57, 196, 97, 228, 162, 121, 34, 100, 81, 169, 123, 25, 0, 158, 102, 177, 198, 60, 174, 14, 125},
        {100, 100, 146, 92, 58, 10, 170, 0, 17, 33, 109, 34, 144, 43, 156, 88, 186, 251, 1, 50, 56, 177, 31, 86, 28, 240, 96, 67, 1, 152, 252, 86}
    },
};

static const auto cipher_key = [] {
    ag::dnscrypt::key_array result;
    std::generate(result.begin(), result.end(), [n = 0]() mutable { return n++; });
    return result;
}();

static const auto cipher_nonce = [] {
    ag::dnscrypt::nonce_array result;
    std::generate(result.begin(), result.end(), [n = result.size()]() mutable { return --n; });
    return result;
}();

static const auto cipher_src = [] {
    ag::uint8_array<10> result;
    result.fill(42);
    return result;
}();

TEST_P(cipher_test, cipher) {
    const auto &[encryption_algorithm, valid_cipher_text, valid_shared_key] = GetParam();
    auto[ciphertext, seal_err] = ag::dnscrypt::cipher_seal(encryption_algorithm, ag::utils::to_string_view(cipher_src),
                                                           cipher_nonce, cipher_key);
    ASSERT_FALSE(seal_err) << "Seal error: " << *seal_err;
    ASSERT_TRUE(std::equal(ciphertext.begin(), ciphertext.end(), std::begin(valid_cipher_text),
                           std::end(valid_cipher_text)));
    auto[decrypted, open_err] = ag::dnscrypt::cipher_open(encryption_algorithm, ag::utils::to_string_view(ciphertext),
                                                          cipher_nonce, cipher_key);
    ASSERT_FALSE(open_err) << "Open error: " << *open_err;
    ASSERT_TRUE(std::equal(cipher_src.begin(), cipher_src.end(), decrypted.begin(), decrypted.end()))
            << "Src and decrypted not equal";
    ++ciphertext.front();
    auto[bad_decrypted, bad_decrypted_err] = ag::dnscrypt::cipher_open(encryption_algorithm,
                                                                       ag::utils::to_string_view(ciphertext),
                                                                       cipher_nonce, cipher_key);
    ASSERT_TRUE(bad_decrypted_err) << "Tag validation failed";
    auto[shared_key, shared_key_err] = ag::dnscrypt::cipher_shared_key(encryption_algorithm, cipher_key, cipher_key);
    ASSERT_FALSE(shared_key_err) << "Can not shared key: " << *shared_key_err;
    ASSERT_TRUE(std::equal(shared_key.begin(), shared_key.end(), std::begin(valid_shared_key),
                           std::end(valid_shared_key)));
}

INSTANTIATE_TEST_CASE_P(cipher_test_instantiation, cipher_test, ::testing::ValuesIn(cipher_test_data_values));

using parse_stamp_test_data_type = std::tuple<const char *, void(*)(const char *, const ag::server_stamp &)>;

static void parse_stamp_test_data_log(const char *stamp_str, const ag::server_stamp &stamp) {
    SPDLOG_INFO(stamp_str);
    SPDLOG_INFO("Protocol={}", stamp.proto);
    SPDLOG_INFO("ProviderName={}", stamp.provider_name);
    SPDLOG_INFO("Path={}", stamp.path);
}

static constexpr parse_stamp_test_data_type parse_stamp_test_data[]{
    {
        // Google DoH
        "sdns://AgUAAAAAAAAAAAAOZG5zLmdvb2dsZS5jb20NL2V4cGVyaW1lbnRhbA",
        parse_stamp_test_data_log
    },
    {
        // AdGuard DNSCrypt
        "sdns://AQIAAAAAAAAAFDE3Ni4xMDMuMTMwLjEzMDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20",
        [](const char *stamp_str, const ag::server_stamp &stamp) {
            parse_stamp_test_data_log(stamp_str, stamp);
            SPDLOG_INFO("ServerAddrStr={}", stamp.server_addr_str);
            SPDLOG_INFO("ServerPk len={}\n", stamp.server_pk.size());
        }
    },
};

struct parse_stamp_test : dnscrypt_test_with_param<parse_stamp_test_data_type> {};

TEST_P(parse_stamp_test, parse_stamp) {
    const auto &stamp_str = std::get<0>(GetParam());
    const auto &log_f = std::get<1>(GetParam());
    auto[stamp, stamp_err] = ag::server_stamp::from_string(stamp_str);
    ASSERT_FALSE(stamp_err || stamp.provider_name.empty()) << "Could not parse stamp " << stamp_str
                                                           << (stamp_err ? ": " + *stamp_err : "");
    log_f(stamp_str, stamp);
}

INSTANTIATE_TEST_CASE_P(parse_stamp_test_instantiation, parse_stamp_test, ::testing::ValuesIn(parse_stamp_test_data));

TEST_F(dnscrypt_test, invalid_stamp) {
    ag::dnscrypt::client client;
    auto err = client.dial("sdns://AQIAAAAAAAAAFDE", ag::dnscrypt::client::DEFAULT_TIMEOUT).error;
    ASSERT_TRUE(err) << "Dial must not have been possible";
}

TEST_F(dnscrypt_test, timeout_on_dial_error) {
    using namespace std::literals::chrono_literals;
    // AdGuard DNS pointing to a wrong IP
    static constexpr auto stamp_str = "sdns://AQIAAAAAAAAADDguOC44Ljg6NTQ0MyDRK0fyUtzywrv4mRCG6vec5EldixbIoMQyLlLKPzkIcyIyLmRuc2NyeXB0LmRlZmF1bHQubnMxLmFkZ3VhcmQuY29t";
    ag::dnscrypt::client client;
    auto err = client.dial(stamp_str, 300ms).error;
    ASSERT_TRUE(err) << "Dial must not have been possible";
}

TEST_F(dnscrypt_test, timeout_on_dial_exchange) {
    using namespace std::literals::chrono_literals;
    // AdGuard DNS
    static constexpr auto stamp_str = "sdns://AQIAAAAAAAAAFDE3Ni4xMDMuMTMwLjEzMDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20";
    ag::dnscrypt::client client;
    auto[server_info, _, dial_err] = client.dial(stamp_str, 300ms);
    ASSERT_FALSE(dial_err) << "Could not establish connection with " << stamp_str;
    // Point it to an IP where there's no DNSCrypt server
    server_info.set_server_address("8.8.8.8:5443");
    auto req = ag::dnscrypt::create_request_ldns_pkt(LDNS_RR_TYPE_A, LDNS_RR_CLASS_IN, LDNS_RD,
                                                     "google-public-dns-a.google.com.",
                                                     ag::dnscrypt::MAX_DNS_UDP_SAFE_PACKET_SIZE);
    ldns_pkt_set_random_id(req.get());
    auto exchange_err = client.exchange(*req, server_info, 300ms).error;
    ASSERT_TRUE(exchange_err) << "Exchange must not have been possible";
}

static constexpr std::string_view check_dns_crypt_server_test_stamps[]{
    // AdGuard DNS
    "sdns://AQIAAAAAAAAAFDE3Ni4xMDMuMTMwLjEzMDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20",
    // AdGuard DNS Family
    "sdns://AQIAAAAAAAAAFDE3Ni4xMDMuMTMwLjEzMjo1NDQzILgxXdexS27jIKRw3C7Wsao5jMnlhvhdRUXWuMm1AFq6ITIuZG5zY3J5cHQuZmFtaWx5Lm5zMS5hZGd1YXJkLmNvbQ",
    // Cisco OpenDNS
    "sdns://AQAAAAAAAAAADjIwOC42Ny4yMjAuMjIwILc1EUAgbyJdPivYItf9aR6hwzzI1maNDL4Ev6vKQ_t5GzIuZG5zY3J5cHQtY2VydC5vcGVuZG5zLmNvbQ",
    // Cisco OpenDNS Family Shield
    "sdns://AQAAAAAAAAAADjIwOC42Ny4yMjAuMTIzILc1EUAgbyJdPivYItf9aR6hwzzI1maNDL4Ev6vKQ_t5GzIuZG5zY3J5cHQtY2VydC5vcGVuZG5zLmNvbQ",
#if 0
    // Quad9 (anycast) dnssec/no-log/filter 9.9.9.9
    "sdns://AQMAAAAAAAAADDkuOS45Ljk6ODQ0MyBnyEe4yHWM0SAkVUO-dWdG3zTfHYTAC4xHA2jfgh2GPhkyLmRuc2NyeXB0LWNlcnQucXVhZDkubmV0",
#endif
#if 0 // Yandex is down temporarily
    // Yandex DNS
    "sdns://AQQAAAAAAAAAEDc3Ljg4LjguNzg6MTUzNTMg04TAccn3RmKvKszVe13MlxTUB7atNgHhrtwG1W1JYyciMi5kbnNjcnlwdC1jZXJ0LmJyb3dzZXIueWFuZGV4Lm5ldA",
#endif
};

static constexpr ag::dnscrypt::protocol check_dns_crypt_server_test_protocols[]{
    ag::dnscrypt::protocol::UDP,
    ag::dnscrypt::protocol::TCP,
};

struct check_dns_crypt_server_test : dnscrypt_test_with_param<::testing::tuple<std::string_view,
                                                                               ag::dnscrypt::protocol>> {};

TEST_P(check_dns_crypt_server_test, check_dns_crypt_server) {
    using namespace std::literals::chrono_literals;
    const auto &stamp_str = std::get<0>(GetParam());
    const auto &protocol = std::get<1>(GetParam());
    ag::dnscrypt::client client(protocol);
    auto[server_info, dial_rtt, dial_err] = client.dial(stamp_str, 10s);
    ASSERT_FALSE(dial_err) << "Could not establish connection with " << stamp_str;
    SPDLOG_INFO("Established a connection with {}, ttl={}, rtt={}ms, protocol={}", server_info.get_provider_name(),
                ag::utils::time_to_str(server_info.get_server_cert().not_after), dial_rtt.count(),
                ag::dnscrypt::protocol_str(protocol));
    auto req = ag::dnscrypt::create_request_ldns_pkt(LDNS_RR_TYPE_A, LDNS_RR_CLASS_IN, LDNS_RD,
                                                     "google-public-dns-a.google.com.",
                                                      ag::utils::make_optional_if(
                                                              protocol == ag::dnscrypt::protocol::UDP,
                                                              ag::dnscrypt::MAX_DNS_UDP_SAFE_PACKET_SIZE));
    ldns_pkt_set_random_id(req.get());
    auto[reply, exchange_rtt, exchange_err] = client.exchange(*req, server_info, 10s);
    ASSERT_FALSE(exchange_err) << "Couldn't talk to upstream " << server_info.get_provider_name() << ": "
                               << *exchange_err;
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
    auto rdf0 = ag::ldns_rdf_ptr(ldns_rdf_new_frm_str(LDNS_RDF_TYPE_A, "8.8.8.8"));
    ASSERT_EQ(sizeof(in_addr), ldns_rdf_size(rdf));
    ASSERT_EQ(ldns_rdf_compare(rdf, rdf0.get()), 0) << "DNS upstream " << server_info.get_provider_name()
                                                    << " returned wrong answer instead of 8.8.8.8: "
                                                    << inet_ntoa(*reinterpret_cast<in_addr*>(ldns_rdf_data(rdf)));
    SPDLOG_INFO("Got proper response from {}, rtt={}ms, protocol={}", server_info.get_provider_name(),
                exchange_rtt.count(), ag::dnscrypt::protocol_str(protocol));
    free(ldns_rdf_data(rdf0.get()));
}

INSTANTIATE_TEST_CASE_P(check_dns_crypt_server_test_instantiation, check_dns_crypt_server_test,
                        ::testing::Combine(::testing::ValuesIn(check_dns_crypt_server_test_stamps),
                                           ::testing::ValuesIn(check_dns_crypt_server_test_protocols)));
