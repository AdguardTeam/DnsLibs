// Deterministic coverage for the plain-DNS hostname upstream peer-eviction
// behavior: when a bootstrapped hostname resolves to several target
// addresses and the selected one fails, the failed peer must be dropped from
// the bootstrap cache so a subsequent UDP/TCP exchange reuses a remaining
// cached address.
//
// The real Bootstrapper caches resolved addresses in a std::unordered_set whose
// iteration order -- and therefore "which resolved address a hostname upstream
// selects first" -- is implementation-defined and differs between stdlibs / CI
// platforms. To make the behavior observable deterministically, this TU replaces
// Bootstrapper with a controllable mock (the same technique used by
// test_dot_invalid_address.cpp): it hands PlainUpstream a fixed, ordered list of
// resolved addresses and drops entries via remove_resolved(). The DNS exchanges
// themselves still run against in-process loopback responders, so the whole
// path is exercised fully offline.

#include <ldns/ldns.h>

#include "common/gtest_coro.h"
#include "common/socket_address.h"
#include "dns/common/event_loop.h"
#include "dns/net/socket.h"
#include "dns/upstream/bootstrapper.h"
#include "dns/upstream/upstream.h"

#include "../resolver.h"
#include "dns_test_helpers.h"
#include "loopback_dns_server.h"

namespace ag::dns {

// The mock bootstrapper hands this ordered list to PlainUpstream as the
// resolved-address cache (the first IPv4 is selected first). Rebuilt per test
// with the live loopback port; the default entries are dead/unusable so no real
// exchange reaches anywhere except the loopback responders.
static std::vector<SocketAddress> RESOLVED_ADDRESSES = {
        SocketAddress("127.0.0.1", 1),
        SocketAddress("127.0.0.2", 1),
};

// Captured by the mock constructor from the Bootstrapper::Params; lets tests
// verify the address string (and thus the normalized port) that
// PlainUpstream::init() passes to the bootstrapper.
static std::string CAPTURED_BOOTSTRAPPER_ADDRESS;

Bootstrapper::Bootstrapper(const Params &p)
        : m_log("bootstrapper test") {
    CAPTURED_BOOTSTRAPPER_ADDRESS = std::string(p.address_string);
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

class PlainEvictionTest : public ::testing::Test {
public:
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

    /** Build a plain-DNS upstream with the given address and a real socket factory. */
    UpstreamFactory::CreateResult create_upstream(const std::string &address, Millis timeout = Millis{1000}) {
        UpstreamFactory factory({
                .loop = *m_loop,
                .socket_factory = m_socket_factory.get(),
                .ipv6_available = false,
                .enable_http3 = false,
                .timeout = timeout,
        });
        return factory.create_upstream({.address = address, .bootstrap = {"127.0.0.1:1"}});
    }

    EventLoopPtr m_loop;
    std::unique_ptr<SocketFactory> m_socket_factory;
};

static ldns_pkt_ptr make_query() {
    return ldns_pkt_ptr{
            ldns_pkt_query_new(ldns_dname_new_frm_str("google.com"), LDNS_RR_TYPE_A, LDNS_RR_CLASS_IN, LDNS_RD)};
}

// The bootstrap cache holds two addresses: a dead loopback IPv4 (selected
// first, so the first exchange fails and must be evicted) and the live loopback
// responder. The first exchange fails, and the second one proves the remaining
// cached address is reused.
TEST_F(PlainEvictionTest, UdpRotatesToRemainingCachedAddress) {
    co_await m_loop->co_submit();
    ag::test::LoopbackDnsServer server{[](const ldns_pkt &req) {
        return ag::test::make_base_reply(req);
    }};
    server.start();

    RESOLVED_ADDRESSES = {
            SocketAddress("127.0.0.1", 1),             // dead IPv4, selected first
            SocketAddress("127.0.0.1", server.port()), // live loopback responder
    };

    auto upstream_res = create_upstream(AG_FMT("localhost:{}", server.port()));
    ASSERT_FALSE(upstream_res.has_error()) << upstream_res.error()->str();

    // The selected (first) peer is dead: the exchange must fail.
    auto first = co_await upstream_res.value()->exchange(make_query().get());
    ASSERT_TRUE(first.has_error()) << "The dead first peer must fail the exchange";

    // The dead peer must have been evicted; the surviving peer answers.
    auto second = co_await upstream_res.value()->exchange(make_query().get());
    ASSERT_FALSE(second.has_error()) << "The remaining cached peer must be reused: " << second.error()->str();
    ASSERT_EQ(ldns_pkt_get_rcode(second->get()), LDNS_RCODE_NOERROR);

    server.stop();
}

// Same rotation over the TCP (framed) path: the connection pool's connect
// chooses the dead address, fails, and evicts it via
// BootstrappedFramedConnection::finish_request; the next exchange reconnects to
// the surviving address.
TEST_F(PlainEvictionTest, TcpRotatesToRemainingCachedAddress) {
    co_await m_loop->co_submit();
    ag::test::LoopbackDnsServer server{[](const ldns_pkt &req) {
        return ag::test::make_base_reply(req);
    }};
    server.start();

    RESOLVED_ADDRESSES = {
            SocketAddress("127.0.0.1", 1),             // dead IPv4, selected first
            SocketAddress("127.0.0.1", server.port()), // live loopback responder
    };

    auto upstream_res = create_upstream(AG_FMT("tcp://localhost:{}", server.port()));
    ASSERT_FALSE(upstream_res.has_error()) << upstream_res.error()->str();

    auto first = co_await upstream_res.value()->exchange(make_query().get());
    ASSERT_TRUE(first.has_error()) << "The dead first peer must fail the exchange";

    auto second = co_await upstream_res.value()->exchange(make_query().get());
    ASSERT_FALSE(second.has_error()) << "The remaining cached peer must be reused: " << second.error()->str();
    ASSERT_EQ(ldns_pkt_get_rcode(second->get()), LDNS_RCODE_NOERROR);

    server.stop();
}

// A `host:0` address must be normalized to the default port before the
// bootstrap address string is built, so the bootstrapper resolves port 53 and
// not port 0 (regression for the plain-IP path, which already treated zero as
// the default port).
TEST_F(PlainEvictionTest, ZeroPortNormalizedBeforeBootstrap) {
    co_await m_loop->co_submit();
    ag::test::LoopbackDnsServer server{[](const ldns_pkt &req) {
        return ag::test::make_base_reply(req);
    }};
    server.start();

    CAPTURED_BOOTSTRAPPER_ADDRESS.clear();
    auto upstream_res = create_upstream("localhost:0");
    ASSERT_FALSE(upstream_res.has_error()) << upstream_res.error()->str();
    ASSERT_EQ(CAPTURED_BOOTSTRAPPER_ADDRESS, AG_FMT("localhost:{}", DEFAULT_PLAIN_PORT));

    server.stop();
}

} // namespace ag::dns::upstream::test
