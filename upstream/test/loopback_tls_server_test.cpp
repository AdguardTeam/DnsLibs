// Smoke test for common/test_helpers/loopback_tls_server.h.
//
// Exchanges a real DNS query through a real DotUpstream against the local
// LoopbackTlsServer and asserts the canned A reply is returned. Fully
// offline: the server is bound to 127.0.0.1, the bootstrapper resolves the
// literal IP immediately (no DNS lookup), and TestCertificateVerifier
// {ACCEPT_ALL} accepts the loopback server's self-signed certificate.
//
// NOTE: this file lives under upstream/test/ (not common/test/) on purpose.
// DotUpstream + UpstreamFactory + SocketFactory are built from the upstream
// and net modules, which common/ cannot link. The header itself remains in
// common/test_helpers/ for reuse by every consuming test target.

#include <array>
#include <cstdint>
#include <cstring>
#include <ldns/ldns.h>

#include "common/gtest_coro.h"
#include "dns/common/event_loop.h"
#include "dns/net/socket.h"
#include "dns/upstream/upstream.h"

#include "dns_test_helpers.h"
#include "loopback_tls_server.h"
#include "test_certificates.h"

namespace ag::dns::upstream::test {

namespace {
// A fixed query id so request/reply matching is deterministic.
constexpr uint16_t QUERY_ID = 0x4242;

// The canned A-record rdata returned by the loopback DoT server.
constexpr std::array<uint8_t, 4> CANNED_A{93, 184, 216, 34};

// Builds a DNS query for `name` with a fixed id.
ldns_pkt_ptr make_query(const char *name, ldns_rr_type type) {
    ldns_pkt *pkt = ldns_pkt_query_new(ldns_dname_new_frm_str(name), type, LDNS_RR_CLASS_IN, LDNS_RD);
    ldns_pkt_set_id(pkt, QUERY_ID);
    return ldns_pkt_ptr{pkt};
}

// Canned A-record (93.184.216.34) reply echoing the request's qname.
// Uses the shared test helpers from dns_test_helpers.h.
ldns_pkt_ptr make_canned_a_reply(const ldns_pkt &request) {
    ldns_pkt_ptr reply = ag::test::make_base_reply(request);
    const ldns_rr *question = ldns_rr_list_rr(ldns_pkt_question(&request), 0);
    if (question == nullptr) {
        return {};
    }
    ldns_rr *answer = ldns_rr_new();
    ldns_rr_set_owner(answer, ldns_rdf_clone(ldns_rr_owner(question)));
    ldns_rr_set_ttl(answer, 300);
    ldns_rr_set_type(answer, LDNS_RR_TYPE_A);
    ldns_rr_set_class(answer, LDNS_RR_CLASS_IN);
    ldns_rr_push_rdf(answer, ldns_rdf_new_frm_str(LDNS_RDF_TYPE_A, "93.184.216.34"));
    ldns_pkt_push_rr(reply.get(), LDNS_SECTION_ANSWER, answer);
    return reply;
}

// Returns an empty string if `reply` is the expected canned A (93.184.216.34)
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
        return "answer data is not 93.184.216.34";
    }
    return {};
}
} // namespace

class LoopbackTlsServerTest : public ::testing::Test {
protected:
    void SetUp() override {
        m_loop = EventLoop::create();
        m_loop->start();
    }

    void TearDown() override {
        m_loop->stop();
        m_loop->join();
    }

    EventLoopPtr m_loop;
};

// Real DotUpstream client exchanges an A query against the local
// LoopbackTlsServer and gets the canned answer, offline.
TEST_F(LoopbackTlsServerTest, DotUpstreamExchangesQueryOffline) {
    co_await m_loop->co_submit();
    ag::test::LoopbackTlsServer server([](const ldns_pkt &request) {
        return make_canned_a_reply(request);
    });
    server.start();

    SocketFactory sf{{
            .loop = *m_loop,
            .verifier = std::make_unique<ag::test::TestCertificateVerifier>(
                    ag::test::TestCertificateVerifier::Mode::ACCEPT_ALL),
    }};
    UpstreamFactory factory({.loop = *m_loop, .socket_factory = &sf, .timeout = Millis{5000}});
    auto upstream_res = factory.create_upstream({.address = server.address()});
    ASSERT_FALSE(upstream_res.has_error()) << upstream_res.error()->str();

    ldns_pkt_ptr req = make_query("example.com.", LDNS_RR_TYPE_A);
    auto reply_res = co_await upstream_res.value()->exchange(req.get());
    ASSERT_FALSE(reply_res.has_error()) << reply_res.error()->str();

    std::string err = check_canned_a_reply(*reply_res.value());
    ASSERT_TRUE(err.empty()) << err;

    server.stop();
}

} // namespace ag::dns::upstream::test
