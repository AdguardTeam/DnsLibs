#include <gtest/gtest.h>
#include <ldns/ldns.h>

#include "../bootstrapper.h"
#include "net/application_verifier.h"
#include "net/socket.h"
#include "upstream/upstream.h"

namespace ag {

std::vector<SocketAddress> RESOLVED_ADDRESSES = {
        SocketAddress("0.0.0.0", 853),
        SocketAddress("::", 853),
        SocketAddress("fe80::cafe:babe", 853),
        SocketAddress("1.2.3.4", 12345),
        SocketAddress("1.1.1.1", 853),
};

Bootstrapper::ResolveResult Bootstrapper::get() {
    return {.addresses = m_resolved_cache};
}

Bootstrapper::Bootstrapper(const Params &p)
        : m_log("bootstrapper test") {
}

ErrString Bootstrapper::init() {
    m_resolved_cache = RESOLVED_ADDRESSES;
    return std::nullopt;
}

void Bootstrapper::remove_resolved(const SocketAddress &a) {
    m_resolved_cache.erase(std::remove(m_resolved_cache.begin(), m_resolved_cache.end(), a), m_resolved_cache.end());
}

std::string Bootstrapper::address() const {
    return "";
}

ErrString Bootstrapper::temporary_disabler_check() {
    return std::nullopt;
}

void Bootstrapper::temporary_disabler_update(const ErrString &error) {
}

Bootstrapper::ResolveResult Bootstrapper::resolve() {
    return {};
}

} // namespace ag

namespace ag::upstream::test {

TEST(DotUpstreamTest, ThrowsAwayInvalidAddress) {
    Logger::set_log_level(LogLevel::LOG_LEVEL_TRACE);
    SocketFactory sf{{
            .verifier = std::make_unique<ApplicationVerifier>([](const CertificateVerificationEvent &) {
                return std::nullopt;
            }),
    }};
    UpstreamFactory factory({.socket_factory = &sf});
    auto [upstream, error] = factory.create_upstream({.address = "tls://cloudflare-dns.com", .bootstrap = {"1.2.3.4"}});
    ASSERT_FALSE(error) << *error;
    bool success = false;
    for (int i = 0; i < RESOLVED_ADDRESSES.size(); ++i) {
        ldns_pkt_ptr pkt{
                ldns_pkt_query_new(ldns_dname_new_frm_str("google.com"), LDNS_RR_TYPE_A, LDNS_RR_CLASS_IN, LDNS_RD)};
        auto [resp, error] = upstream->exchange(pkt.get());
        if (!error && ldns_pkt_get_rcode(resp.get()) == LDNS_RCODE_NOERROR) {
            success = true;
            break;
        }
    }
    ASSERT_TRUE(success);
}

} // namespace ag::upstream::test
