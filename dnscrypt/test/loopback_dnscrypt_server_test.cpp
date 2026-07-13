// Smoke test for common/test_helpers/loopback_dnscrypt_server.h.
//
// Drives a real dnscrypt::Client (cert fetch + key exchange + encrypted relay)
// against the in-process LoopbackDnscryptServer bound to 127.0.0.1, and asserts
// the canned A reply comes back. Fully offline: no real DNSCrypt resolver, no
// public internet. Parametrized over the two supported crypto constructions
// (X_SALSA_20_POLY_1305, X_CHACHA_20_POLY_1305) and both transports (UDP/TCP).
//
// NOTE: this file lives under dnscrypt/test/ because the real client
// (dnscrypt::Client) and its SocketFactory/EventLoop dependencies come from the
// dnscrypt + net modules. The header itself remains in common/test_helpers/.

#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <ldns/ldns.h>
#include <magic_enum/magic_enum.hpp>
#include <sodium.h>
#include <tuple>

#include "common/gtest_coro.h"
#include "common/logger.h"
#include "dns/common/dns_defs.h"
#include "dns/common/event_loop.h"
#include "dns/dnscrypt/dns_crypt_client.h"
#include "dns/dnscrypt/dns_crypt_ldns.h"
#include "dns/dnscrypt/dns_crypt_utils.h"
#include "dns/net/socket.h"

#include "loopback_dnscrypt_server.h"

namespace ag::dns::dnscrypt::test {

namespace {

constexpr uint16_t QUERY_ID = 0x4242;

// The canned A-record rdata returned by the loopback server's handler.
constexpr std::array<uint8_t, 4> CANNED_A{1, 2, 3, 4};

// Builds a DNS query for `name` with a fixed id.
ldns_pkt_ptr make_query(const char *name, ldns_rr_type type) {
    ldns_pkt *pkt = ldns_pkt_query_new(ldns_dname_new_frm_str(name), type, LDNS_RR_CLASS_IN, LDNS_RD);
    ldns_pkt_set_id(pkt, QUERY_ID);
    return ldns_pkt_ptr{pkt};
}

// Canned A-record (1.2.3.4) reply echoing the request's qname.
ldns_pkt_ptr make_canned_a_reply(const ldns_pkt &request) {
    ldns_pkt_ptr reply{ldns_pkt_clone(&request)};
    ldns_pkt_set_qr(reply.get(), true);
    ldns_pkt_set_ra(reply.get(), true);
    ldns_pkt_set_rcode(reply.get(), LDNS_RCODE_NOERROR);
    const ldns_rr *question = ldns_rr_list_rr(ldns_pkt_question(&request), 0);
    if (question == nullptr) {
        return {};
    }
    ldns_rr *answer = ldns_rr_new();
    ldns_rr_set_owner(answer, ldns_rdf_clone(ldns_rr_owner(question)));
    ldns_rr_set_ttl(answer, 300);
    ldns_rr_set_type(answer, LDNS_RR_TYPE_A);
    ldns_rr_set_class(answer, LDNS_RR_CLASS_IN);
    ldns_rr_push_rdf(answer, ldns_rdf_new_frm_str(LDNS_RDF_TYPE_A, "1.2.3.4"));
    ldns_pkt_push_rr(reply.get(), LDNS_SECTION_ANSWER, answer);
    return reply;
}

// Returns an empty string if `reply` is the expected canned A (1.2.3.4)
// response, otherwise a human-readable description of the mismatch. Kept
// ASSERT-free so it can be called from a helper (ASSERT_* expands to a
// coroutine co_return under gtest_coro, which is only valid in a test body).
std::string check_canned_a_reply(const ldns_pkt &reply) {
    if (ldns_pkt_get_rcode(&reply) != LDNS_RCODE_NOERROR) {
        return "expected NOERROR rcode";
    }
    if (ldns_pkt_ancount(&reply) != 1u) {
        return "expected exactly one answer";
    }
    const ldns_rr *answer = ldns_rr_list_rr(ldns_pkt_answer(&reply), 0);
    if (answer == nullptr) {
        return "answer section is empty";
    }
    if (ldns_rr_get_type(answer) != LDNS_RR_TYPE_A) {
        return "expected an A answer";
    }
    const ldns_rdf *rdf = ldns_rr_rdf(answer, 0);
    if (rdf == nullptr) {
        return "answer has no rdata";
    }
    if (ldns_rdf_size(rdf) != CANNED_A.size()
            || std::memcmp(ldns_rdf_data(rdf), CANNED_A.data(), CANNED_A.size()) != 0) {
        return "answer data is not 1.2.3.4";
    }
    return {};
}

struct LoopbackParam {
    CryptoConstruction algo;
    utils::TransportProtocol proto;
};

std::string param_name(const testing::TestParamInfo<LoopbackParam> &info) {
    return std::string{magic_enum::enum_name(info.param.algo)} + "_"
            + std::string{magic_enum::enum_name(info.param.proto)};
}

const LoopbackParam loopback_params[]{
        {CryptoConstruction::X_SALSA_20_POLY_1305, utils::TransportProtocol::TP_UDP},
        {CryptoConstruction::X_SALSA_20_POLY_1305, utils::TransportProtocol::TP_TCP},
        {CryptoConstruction::X_CHACHA_20_POLY_1305, utils::TransportProtocol::TP_UDP},
        {CryptoConstruction::X_CHACHA_20_POLY_1305, utils::TransportProtocol::TP_TCP},
};

} // namespace

class LoopbackDnscryptServerTest : public testing::TestWithParam<LoopbackParam> {
protected:
    void SetUp() override {
        Logger::set_log_level(LOG_LEVEL_TRACE);
        m_loop = EventLoop::create();
        m_loop->start();
        m_socket_factory = std::make_unique<SocketFactory>(SocketFactory::Parameters{.loop = *m_loop});
    }

    void TearDown() override {
        m_socket_factory.reset();
        m_loop->stop();
        m_loop->join();
    }

    EventLoopPtr m_loop;
    std::unique_ptr<SocketFactory> m_socket_factory;
};

// Real dnscrypt::Client dials (cert fetch + verify + key exchange) and
// exchanges an A query against the local LoopbackDnscryptServer, offline,
// returning the canned answer.
TEST_P(LoopbackDnscryptServerTest, ClientDialsAndExchangesOffline) {
    (void) ::sodium_init();
    co_await m_loop->co_submit();
    const auto &param = GetParam();

    ag::test::LoopbackDnscryptServer server(
            [](const ldns_pkt &request) {
                return make_canned_a_reply(request);
            },
            param.algo);
    server.start();

    Client client(param.proto);
    using namespace std::literals::chrono_literals;
    auto dial_res = co_await client.dial(server.stamp(), *m_loop, 5000ms, m_socket_factory.get(), {});
    ASSERT_FALSE(dial_res.has_error()) << "Could not dial the loopback DNSCrypt server: " << dial_res.error()->str();
    auto &[server_info, dial_rtt] = *dial_res;
    (void) dial_rtt;
    ASSERT_EQ(server_info.get_server_cert().encryption_algorithm, param.algo);

    ldns_pkt_ptr req = make_query("example.com.", LDNS_RR_TYPE_A);
    ldns_pkt_set_random_id(req.get());
    auto exchange_res = co_await client.exchange(*req, server_info, *m_loop, 5000ms, m_socket_factory.get(), {});
    ASSERT_FALSE(exchange_res.has_error())
            << "Couldn't exchange with the loopback DNSCrypt server: " << exchange_res.error()->str();
    auto &[reply, exchange_rtt] = *exchange_res;
    (void) exchange_rtt;
    std::string err = check_canned_a_reply(*reply);
    ASSERT_TRUE(err.empty()) << err;

    server.stop();
}

INSTANTIATE_TEST_SUITE_P(LoopbackDnscryptServerInstantiation, LoopbackDnscryptServerTest,
        testing::ValuesIn(loopback_params), param_name);

} // namespace ag::dns::dnscrypt::test
