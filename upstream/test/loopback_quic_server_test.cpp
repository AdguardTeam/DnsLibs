// Smoke test for common/test_helpers/loopback_quic_server.h.
//
// Exchanges real DNS queries through real DoqUpstream and DohUpstream clients
// against the local LoopbackQuicServer (DoQ — ALPN "doq", RFC 9250 2-byte
// stream framing; DoH3 — ALPN "h3", HTTP/3 over QUIC via Http3Server::accept)
// and asserts the canned A reply is returned. Fully offline: the server is
// bound to 127.0.0.1 (the bootstrapper resolves the literal IP immediately, no
// DNS lookup), and TestCertificateVerifier{ACCEPT_ALL} accepts the loopback
// server's self-signed certificate.
//
// This is the first in-repo exercise of `ngtcp2_conn_server_new` +
// `ngtcp2_crypto_boringssl_configure_server_context`; the server-side QUIC/TLS
// plumbing does not exist elsewhere in this repo's own source.
//
// NOTE: this file lives under upstream/test/ (not common/test/) on purpose.
// DoqUpstream + UpstreamFactory + SocketFactory are built from the upstream
// and net modules, which common/ cannot link. The header itself remains in
// common/test_helpers/ for reuse by every consuming test target.

#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <ldns/ldns.h>

#include "common/gtest_coro.h"
#include "dns/common/event_loop.h"
#include "dns/net/socket.h"
#include "dns/upstream/upstream.h"

#include "dns_test_helpers.h"
#include "loopback_dns_server.h"
#include "loopback_quic_server.h"
#include "test_certificates.h"

namespace ag::dns::upstream::test {

namespace {
// The canned A-record rdata returned by the loopback DoQ server.
constexpr std::array<uint8_t, 4> CANNED_A{8, 8, 8, 8};

// Builds a DNS query for `name`. The DoQ client rewrites the query id to 0 per
// RFC 9250 before sending, so the id here is immaterial for matching; the
// server echoes whatever it receives.
ldns_pkt_ptr make_query(const char *name, ldns_rr_type type) {
    ldns_pkt *pkt = ldns_pkt_query_new(ldns_dname_new_frm_str(name), type, LDNS_RR_CLASS_IN, LDNS_RD);
    return ldns_pkt_ptr{pkt};
}

// Canned A-record (8.8.8.8) reply echoing the request's qname.
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
    ldns_rr_push_rdf(answer, ldns_rdf_new_frm_str(LDNS_RDF_TYPE_A, "8.8.8.8"));
    ldns_pkt_push_rr(reply.get(), LDNS_SECTION_ANSWER, answer);
    return reply;
}

// Returns an empty string if `reply` is the expected canned A (8.8.8.8)
// response, otherwise a human-readable description of the mismatch. Kept
// ASSERT-free so it can be called from a helper (ASSERT_* expands to a
// coroutine co_return under gtest_coro, only valid in a test body).
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
        return "answer data is not 8.8.8.8";
    }
    return {};
}
} // namespace

class LoopbackQuicServerTest : public ::testing::Test {
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

// Real DoqUpstream client exchanges an A query against the local
// LoopbackQuicServer (DoQ mode) and gets the canned answer, offline.
TEST_F(LoopbackQuicServerTest, DoqUpstreamExchangesQueryOffline) {
    co_await m_loop->co_submit();
    ag::test::LoopbackQuicServer server([](const ldns_pkt &request) {
        return make_canned_a_reply(request);
    });
    server.start();

    SocketFactory sf{{
            .loop = *m_loop,
            .verifier = std::make_unique<ag::test::TestCertificateVerifier>(
                    ag::test::TestCertificateVerifier::Mode::ACCEPT_ALL),
    }};
    UpstreamFactory factory({.loop = *m_loop, .socket_factory = &sf, .timeout = Millis{10000}});
    auto upstream_res = factory.create_upstream({.address = server.address()});
    ASSERT_FALSE(upstream_res.has_error()) << upstream_res.error()->str();

    ldns_pkt_ptr req = make_query("example.com.", LDNS_RR_TYPE_A);
    auto reply_res = co_await upstream_res.value()->exchange(req.get());
    ASSERT_FALSE(reply_res.has_error()) << reply_res.error()->str();

    std::string err = check_canned_a_reply(*reply_res.value());
    ASSERT_TRUE(err.empty()) << err;

    server.stop();
}

// Regression test for the multi-address Initial-flight replay in DoqUpstream:
// the client races one IPv6 + one IPv4 address (see reinit()), and the IPv6
// socket is always created first. When that IPv6 path is dead (e.g. an
// unroutable documentation address behind a blackhole route), the client must
// immediately replay the cached Initial flight on the IPv4 socket instead of
// burning a full PTO (~500ms) waiting for a retransmission, so the exchange
// must complete well below one PTO interval.
TEST_F(LoopbackQuicServerTest, DoqUpstreamSkipsDeadIpv6PathWithoutPto) {
    co_await m_loop->co_submit();

    // The replay branch requires a connectable IPv6 candidate: the client
    // always races IPv6 first, and on a host without IPv6 sockets the IPv6
    // connect() fails fast, degrading this test to an ordinary IPv4-only pass
    // that never exercises the replay. Probe IPv6 socket creation and skip
    // explicitly instead of silently passing.
    ag::test::detail::ensure_winsock();
    auto ipv6_probe = ag::test::detail::open_dgram_socket6();
    if (ipv6_probe == ag::test::detail::invalid_socket()) {
        GTEST_SKIP() << "Host has no IPv6 sockets; the dead-IPv6 Initial-flight replay path cannot be exercised";
    }
    ag::test::detail::close_fd(ipv6_probe);

    ag::test::LoopbackQuicServer server([](const ldns_pkt &request) {
        return make_canned_a_reply(request);
    });
    server.start();

    // Resolves "quic.test" to a documentation-only (unroutable) IPv6 address
    // first, then the loopback DoQ server's address.
    ag::test::LoopbackDnsServer dns([](const ldns_pkt &request) {
        ldns_pkt_ptr reply = ag::test::make_base_reply(request);
        const ldns_rr *question = ldns_rr_list_rr(ldns_pkt_question(&request), 0);
        if (question == nullptr) {
            return reply;
        }
        if (ldns_rr_get_type(question) == LDNS_RR_TYPE_AAAA) {
            ag::test::add_rr_from_str(reply.get(), "quic.test. 300 IN AAAA 2001:db8::1");
        } else {
            ag::test::add_rr_from_str(reply.get(), "quic.test. 300 IN A 127.0.0.1");
        }
        return reply;
    });
    dns.start();

    SocketFactory sf{{
            .loop = *m_loop,
            .verifier = std::make_unique<ag::test::TestCertificateVerifier>(
                    ag::test::TestCertificateVerifier::Mode::ACCEPT_ALL),
    }};
    UpstreamFactory factory({.loop = *m_loop, .socket_factory = &sf, .timeout = Millis{10000}});
    auto upstream_res = factory.create_upstream({.address = AG_FMT("quic://quic.test:{}", server.port()),
            .bootstrap = {AG_FMT("127.0.0.1:{}", dns.port())}});
    ASSERT_FALSE(upstream_res.has_error()) << upstream_res.error()->str();

    ldns_pkt_ptr req = make_query("example.com.", LDNS_RR_TYPE_A);
    auto start = std::chrono::steady_clock::now();
    auto reply_res = co_await upstream_res.value()->exchange(req.get());
    auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start);
    ASSERT_FALSE(reply_res.has_error()) << reply_res.error()->str();

    std::string err = check_canned_a_reply(*reply_res.value());
    ASSERT_TRUE(err.empty()) << err;

    // Without the Initial-flight replay the dead IPv6 path costs a full PTO
    // (~500ms) before the IPv4 socket is tried; with the fix the exchange
    // completes in a couple of loopback RTTs.
    ASSERT_LT(elapsed_ms.count(), 400) << "DoQ init waited for a PTO retransmission on the dead IPv6 path";

    server.stop();
}

// Real DohUpstream client (HTTP/3 via the "h3://" scheme) exchanges an A query
// against the local LoopbackQuicServer (DoH3 mode) and gets the canned answer,
// offline. Exercises the Http3Server::accept() + on_request → ?dns= →
// submit_response/submit_body path end-to-end.
TEST_F(LoopbackQuicServerTest, Doh3UpstreamExchangesQueryOffline) {
    co_await m_loop->co_submit();
    ag::test::LoopbackQuicServer server(
            [](const ldns_pkt &request) {
                return make_canned_a_reply(request);
            },
            ag::test::LoopbackQuicServer::QuicMode::DOH3);
    server.start();

    SocketFactory sf{{
            .loop = *m_loop,
            .verifier = std::make_unique<ag::test::TestCertificateVerifier>(
                    ag::test::TestCertificateVerifier::Mode::ACCEPT_ALL),
    }};
    UpstreamFactory factory({.loop = *m_loop, .socket_factory = &sf, .timeout = Millis{10000}});
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
