// Smoke test for common/test_helpers/loopback_doh_server.h.
//
// Exchanges a real DNS query through a real DohUpstream client against the
// local LoopbackDohServer and asserts the canned A reply is returned, for both
// the HTTP/1.1 and HTTP/2 negotiation paths. Fully offline: the server is
// bound to 127.0.0.1, the bootstrapper resolves the literal IP immediately (no
// DNS lookup), and TestCertificateVerifier{ACCEPT_ALL} accepts the loopback
// server's self-signed certificate.
//
// ALPN selection (approach): the DohUpstream client always offers both ALPNs
// ["h2","http/1.1"] (see DohUpstream::Http1Or2Connection::establish) and exposes no option to restrict
// the offer, so the negotiated protocol is controlled from the server side.
// The H2 path is exercised with AlpnMode::PREFER_H2 (server selects "h2");
// the H1 path is exercised with AlpnMode::H1_ONLY (server selects "http/1.1").
//
// NOTE: this file lives under upstream/test/ (not common/test/) on purpose.
// DohUpstream + UpstreamFactory + SocketFactory are built from the upstream
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
#include "loopback_doh_server.h"
#include "test_certificates.h"

namespace ag::dns::upstream::test {

namespace {
// The canned A-record rdata returned by the loopback DoH server.
constexpr std::array<uint8_t, 4> CANNED_A{93, 184, 216, 34};

// Builds a DNS query for `name`. The DoH client rewrites the query id to 0
// (RFC 8484) before sending, so the id here is immaterial for matching; the
// server echoes whatever it receives.
ldns_pkt_ptr make_query(const char *name, ldns_rr_type type) {
    ldns_pkt *pkt = ldns_pkt_query_new(ldns_dname_new_frm_str(name), type, LDNS_RR_CLASS_IN, LDNS_RD);
    return ldns_pkt_ptr{pkt};
}

// Canned A-record (93.184.216.34) reply echoing the request's qname.
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
// ASSERT-free so it can be called from either test body.
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

class LoopbackDohServerTest : public ::testing::Test {
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

// Real DohUpstream client exchanges an A query against the local
// LoopbackDohServer over HTTP/2 and gets the canned answer, offline.
TEST_F(LoopbackDohServerTest, DohUpstreamExchangesQueryOverHttp2) {
    co_await m_loop->co_submit();
    ag::test::LoopbackDohServer server(
            [](const ldns_pkt &request) {
                return make_canned_a_reply(request);
            },
            "/dns-query", ag::test::LoopbackDohServer::AlpnMode::PREFER_H2);
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

// Same exchange, but the server advertises only "http/1.1" so the client
// negotiates the HTTP/1.1 path.
TEST_F(LoopbackDohServerTest, DohUpstreamExchangesQueryOverHttp1) {
    co_await m_loop->co_submit();
    ag::test::LoopbackDohServer server(
            [](const ldns_pkt &request) {
                return make_canned_a_reply(request);
            },
            "/dns-query", ag::test::LoopbackDohServer::AlpnMode::H1_ONLY);
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
