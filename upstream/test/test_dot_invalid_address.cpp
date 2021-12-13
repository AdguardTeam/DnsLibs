#include <gtest/gtest.h>
#include <bootstrapper.h>
#include <upstream.h>
#include <ag_socket.h>
#include <application_verifier.h>
#include <ldns/ldns.h>

std::vector<ag::SocketAddress> RESOLVED_ADDRESSES = {
        ag::SocketAddress("0.0.0.0", 853),
        ag::SocketAddress("::", 853),
        ag::SocketAddress("fe80::cafe:babe", 853),
        ag::SocketAddress("1.2.3.4", 12345),
        ag::SocketAddress("1.1.1.1", 853),
};

ag::bootstrapper::resolve_result ag::bootstrapper::get() {
    return { .addresses = m_resolved_cache };
}
ag::bootstrapper::bootstrapper(const params &p) : m_log("bootstrapper test"){}
ag::ErrString ag::bootstrapper::init() {
    m_resolved_cache = RESOLVED_ADDRESSES;
    return std::nullopt;
}
void ag::bootstrapper::remove_resolved(const SocketAddress &a) {
    m_resolved_cache.erase(std::remove(m_resolved_cache.begin(), m_resolved_cache.end(), a), m_resolved_cache.end());
}
std::string ag::bootstrapper::address() const { return ""; }
ag::ErrString ag::bootstrapper::temporary_disabler_check() { return std::nullopt; }
void ag::bootstrapper::temporary_disabler_update(const ErrString &error) {}
ag::bootstrapper::resolve_result ag::bootstrapper::resolve() { return {}; }


TEST(upstream_dot_test, throws_away_invalid_address) {
    ag::Logger::set_log_level(ag::LogLevel::LOG_LEVEL_TRACE);
    ag::socket_factory sf{{
                                  .verifier = std::make_unique<ag::application_verifier>(
                                          [](const ag::certificate_verification_event &) {
                                              return std::nullopt;
                                          }),
                          }};
    ag::upstream_factory factory({.socket_factory = &sf});
    auto[upstream, error] = factory.create_upstream({.address = "tls://cloudflare-dns.com", .bootstrap = {"1.2.3.4"}});
    ASSERT_FALSE(error) << *error;
    bool success = false;
    for (int i = 0; i < RESOLVED_ADDRESSES.size(); ++i) {
        ag::ldns_pkt_ptr pkt{ldns_pkt_query_new(ldns_dname_new_frm_str("google.com"), LDNS_RR_TYPE_A, LDNS_RR_CLASS_IN, LDNS_RD)};
        auto[resp, error] = upstream->exchange(pkt.get());
        if (!error && ldns_pkt_get_rcode(resp.get()) == LDNS_RCODE_NOERROR) {
            success = true;
            break;
        }
    }
    ASSERT_TRUE(success);
}
