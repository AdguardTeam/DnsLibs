#include <ldns/ldns.h>

#include "common/gtest_coro.h"
#include "dns/net/socket.h"
#include "dns/upstream/bootstrapper.h"
#include "dns/upstream/upstream.h"

#include "../resolver.h"
#include "dns_test_helpers.h"
#include "loopback_tls_server.h"
#include "test_certificates.h"

namespace ag::dns {

// The mock bootstrapper hands this list to DotUpstream as the resolved address
// cache. It is rebuilt in the test body with the loopback DoT server's live
// port; the default (mutable) entries are dead loopback / unusable addresses
// so no real IP ever leaks into the default suite.
std::vector<SocketAddress> RESOLVED_ADDRESSES = {
        SocketAddress("0.0.0.0", 853),
        SocketAddress("::", 853),
        SocketAddress("fe80::cafe:babe", 853),
        SocketAddress("127.0.0.1", 1),
        SocketAddress("127.0.0.1", 1),
};

Bootstrapper::Bootstrapper(const Params &p)
        : m_log("bootstrapper test") {
}

Bootstrapper::~Bootstrapper() = default;
Bootstrapper::Bootstrapper(Bootstrapper &&) = default;
Bootstrapper &Bootstrapper::operator=(Bootstrapper &&) = default;

Error<Bootstrapper::BootstrapperError> Bootstrapper::init() {
    m_resolved_cache = RESOLVED_ADDRESSES;
    return {};
}

void Bootstrapper::remove_resolved(const SocketAddress &a) {
    m_resolved_cache.erase(std::remove(m_resolved_cache.begin(), m_resolved_cache.end(), a), m_resolved_cache.end());
}

std::string Bootstrapper::address() const {
    return "";
}

Error<Bootstrapper::BootstrapperError> Bootstrapper::temporary_disabler_check() {
    return {};
}

void Bootstrapper::temporary_disabler_update(bool) {
}

coro::Task<void> Bootstrapper::do_resolve() {
    co_return;
}

void Bootstrapper::complete_resolve(ResolveResult) {
}

std::optional<Bootstrapper::ResolveResult> Bootstrapper::try_get_ready_result() {
    return ResolveResult{m_resolved_cache, m_server_name, Millis(0), {}};
}

// NOLINTNEXTLINE(cppcoreguidelines-rvalue-reference-param-not-moved)
void Bootstrapper::request_resolve(std::function<void(ag::dns::Bootstrapper::ResolveResult)> &&handler) {
}

} // namespace ag::dns

namespace ag::dns::upstream::test {

class DotUpstreamTest : public ::testing::Test {
public:
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

TEST_F(DotUpstreamTest, ThrowsAwayInvalidAddress) {
    co_await m_loop->co_submit();
    Logger::set_log_level(LogLevel::LOG_LEVEL_TRACE);

    // Loopback DoT responder: returns NOERROR to any query, so the loopback
    // entry in RESOLVED_ADDRESSES succeeds while the garbage entries fail and
    // are removed from the bootstrapper cache ("thrown away"). The cert is
    // accepted by TestCertificateVerifier{ACCEPT_ALL}.
    ag::test::LoopbackTlsServer tls_server{[](const ldns_pkt &req) {
        return ag::test::make_base_reply(req);
    }};
    tls_server.start();

    // Rebuild the cache: garbage/unusable addresses first (each tried as the
    // first IPv4/IPv6 candidate and removed on failure), with the live loopback
    // DoT address last so it's reached after the cache eviction cycle.
    RESOLVED_ADDRESSES = {
            SocketAddress("0.0.0.0", 853),                 // invalid IPv4 (loopback, fails fast)
            SocketAddress("::", 853),                      // invalid IPv6 (loopback, fails fast)
            SocketAddress("fe80::cafe:babe", 853),         // invalid IPv6 (unassigned, fails fast)
            SocketAddress("127.0.0.1", 1),                 // dead loopback IPv4 (refused fast)
            SocketAddress("127.0.0.1", tls_server.port()), // live loopback DoT
    };

    SocketFactory sf{{
            .loop = *m_loop,
            .verifier = std::make_unique<ag::test::TestCertificateVerifier>(
                    ag::test::TestCertificateVerifier::Mode::ACCEPT_ALL),
    }};
    UpstreamFactory factory({.loop = *m_loop, .socket_factory = &sf});
    // The mock bootstrapper ignores the bootstrap and returns RESOLVED_ADDRESSES;
    // a hostname upstream ensures init() does not short-circuit on a literal IP.
    auto upstream_res = factory.create_upstream({.address = "tls://localhost", .bootstrap = {"127.0.0.1:1"}});
    ASSERT_FALSE(upstream_res.has_error()) << upstream_res.error()->str();
    bool success = false;
    for (size_t i = 0; i < RESOLVED_ADDRESSES.size(); ++i) {
        ldns_pkt_ptr pkt{
                ldns_pkt_query_new(ldns_dname_new_frm_str("google.com"), LDNS_RR_TYPE_A, LDNS_RR_CLASS_IN, LDNS_RD)};
        auto res = co_await upstream_res.value()->exchange(pkt.get());
        if (!res.has_error() && ldns_pkt_get_rcode(res->get()) == LDNS_RCODE_NOERROR) {
            success = true;
            break;
        }
    }
    ASSERT_TRUE(success);

    tls_server.stop();
}

} // namespace ag::dns::upstream::test
