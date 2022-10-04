#include <ldns/ldns.h>

#include "common/gtest_coro.h"
#include "dns/net/application_verifier.h"
#include "dns/net/socket.h"
#include "dns/upstream/bootstrapper.h"
#include "dns/upstream/upstream.h"

#include "../resolver.h"

namespace ag::dns {

std::vector<SocketAddress> RESOLVED_ADDRESSES = {
        SocketAddress("0.0.0.0", 853),
        SocketAddress("::", 853),
        SocketAddress("fe80::cafe:babe", 853),
        SocketAddress("1.2.3.4", 12345),
        SocketAddress("1.1.1.1", 853),
};

coro::Task<Bootstrapper::ResolveResult> Bootstrapper::get() {
    co_return {.addresses = m_resolved_cache};
}

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

coro::Task<Bootstrapper::ResolveResult> Bootstrapper::resolve() {
    co_return {};
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
    SocketFactory sf{{
            .loop = *m_loop,
            .verifier = std::make_unique<ApplicationVerifier>([](const CertificateVerificationEvent &) {
                return std::nullopt;
            }),
    }};
    UpstreamFactory factory({.loop = *m_loop, .socket_factory = &sf});
    auto upstream_res = factory.create_upstream({.address = "tls://cloudflare-dns.com", .bootstrap = {"1.2.3.4"}});
    ASSERT_FALSE(upstream_res.has_error()) << upstream_res.error()->str();
    bool success = false;
    for (int i = 0; i < RESOLVED_ADDRESSES.size(); ++i) {
        ldns_pkt_ptr pkt{
                ldns_pkt_query_new(ldns_dname_new_frm_str("google.com"), LDNS_RR_TYPE_A, LDNS_RR_CLASS_IN, LDNS_RD)};
        auto res = co_await upstream_res.value()->exchange(pkt.get());
        if (!res.has_error() && ldns_pkt_get_rcode(res->get()) == LDNS_RCODE_NOERROR) {
            success = true;
            break;
        }
    }
    ASSERT_TRUE(success);
}

} // namespace ag::dns::upstream::test
