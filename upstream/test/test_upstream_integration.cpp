// Integration tests: real-public-network upstream exchanges across all
// protocols (gated) and the dead-outbound-proxy failure suite. Shared
// infrastructure comes from upstream_test_fixture.h.

#include <tuple>

#include "upstream_test_fixture.h"

namespace ag::dns::upstream::test {

// Integration-only: real upstreams across all supported protocols (plain DNS,
// DoT, DoH, DoH3, DoQ, DNSCrypt). Testing against real servers validates the
// real handshake and resolution path, which a loopback server can't fully
// reproduce. Gated so the default suite stays offline; the offline loopback
// counterparts live in TestUpstreams{Local,DotLocal,DohLocal,DnscryptLocal,
// DoqDoh3Local} (always-on).
static const UpstreamTestData real_upstreams_data[]{
        {"udp://1.1.1.1:53", {}},
        {"tcp://8.8.8.8", {}},
#ifdef __APPLE__
        {"system://en0", {}},
#endif
#ifdef __ANDROID__
        {"system://", {}},
        {"system://eth0", {}},
#endif
        {"8.8.8.8:53", {"8.8.8.8:53"}},
        {"1.0.0.1", {}},
        {"1.1.1.1", {"1.0.0.1"}},
        {"tcp://1.1.1.1:53", {}},
        {"94.140.14.14:5353", {}},
        {"tls://1.1.1.1", {}},
        {"tls://9.9.9.9:853", {}},
        {"tls://dns.google", {"8.8.8.8:53"}},
        {"tls://dns.google:853", {"8.8.8.8:53"}},
        {"tls://dns.google:853", {"8.8.8.8"}},
        {"tls://one.one.one.one", {"1.0.0.1"}},
        {"https://dns9.quad9.net:443/dns-query", {"8.8.8.8"}},
        {"https://dns.cloudflare.com/dns-query", {"8.8.8.8:53"}},
        {"h3://cloudflare-dns.com/dns-query", {"8.8.8.8"}},
        {"https://dns.google/dns-query", {"8.8.8.8"}},
        {"https://username:password@dns.google/dns-query", {"8.8.8.8"}},
        {"sdns://username:password@AgcAAAAAAAAABzEuMC4wLjEAEmRucy5jbG91ZGZsYXJlLmNvbQovZG5zLXF1ZXJ5", {}},
        {// Cisco OpenDNS DNS (DNSCrypt) (no port in stamp, default port test)
                "sdns://"
                "AQEAAAAAAAAADjIwOC42Ny4yMjAuMTIzILc1EUAgbyJdPivYItf9aR6hwzzI1maNDL4Ev6vKQ_"
                "t5GzIuZG5zY3J5cHQtY2VydC5vcGVuZG5zLmNvbQ"},
        {// AdGuard DNS (DNSCrypt)
                "sdns://"
                "AQIAAAAAAAAAETk0LjE0MC4xNC4xNDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_"
                "OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20",
                {}},
        {// AdGuard Family (DNSCrypt)
                "sdns://"
                "AQIAAAAAAAAAETk0LjE0MC4xNC4xNTo1NDQzILgxXdexS27jIKRw3C7Wsao5jMnlhvhdRUXWuMm1AFq6ITIuZG5zY3J5cHQuZmFta"
                "x5Lm5zMS5hZGd1YXJkLmNvbQ",
                {"8.8.8.8"}},
        {// Cloudflare DNS (DoH)
                "sdns://AgcAAAAAAAAABzEuMC4wLjEAEmRucy5jbG91ZGZsYXJlLmNvbQovZG5zLXF1ZXJ5", {"8.8.8.8:53"}},
        {// Google (Plain)
                "sdns://AAcAAAAAAAAABzguOC44Ljg", {}},
        {// AdGuard DNS (DNS-over-TLS)
                "sdns://AwAAAAAAAAAAAAAPZG5zLmFkZ3VhcmQuY29t", {"8.8.8.8:53"}},
        {// DoT 1.1.1.1
                "sdns://AwAAAAAAAAAAAAAHMS4xLjEuMQ", {"8.8.8.8:53"}},
        {// Cloudflare DNS
                "https://1.1.1.1/dns-query", {}},
        {// AdGuard DNS (DNS-over-QUIC)
                "quic://dns.adguard-dns.com", {"8.8.8.8:53"}},
        {// AdGuard DNS (DNS-over-QUIC) custom port
                "quic://dns.adguard-dns.com:8853", {"8.8.8.8:53"}},
        {// AdGuard DNS (DNS-over-QUIC) stamp with only the port specified in server address field
                "sdns://BAAAAAAAAAAABDo4NTMAE2Rucy5hZGd1YXJkLWRucy5jb20", {"8.8.8.8:53"}},
};

// Real upstreams across all protocols. Only runs when
// DNSLIBS_INTEGRATION_TESTS is set; otherwise SKIPPED so the default suite
// never touches the public internet. (Offline loopback counterparts for each
// protocol family live in TestUpstreams{Local,DotLocal,DohLocal,DnscryptLocal,
// DoqDoh3Local}.)
TEST_F(UpstreamTest, TestUpstreamsIntegration) {
    REQUIRE_INTEGRATION();
#ifdef __linux__
    int fd_count_before = count_open_fds();
#endif
    ASSERT_NO_FATAL_FAILURE(co_await sequential_test(real_upstreams_data, DELAY_BETWEEN_REQUESTS));
#ifdef __linux__
    co_await wait_for_fds_to_stabilize(*m_loop, fd_count_before);
    int fd_count_after = count_open_fds();
    ASSERT_TRUE(fd_count_before <= fd_count_after);
    ASSERT_TRUE(fd_count_after <= fd_count_before + 1);
#endif
}

// Real `8.8.8.8` plain DNS with default options. Gated. (The DoT default-options
// check moved to UpstreamDefaultOptionsLocal against the loopback TLS server.)
TEST_F(UpstreamTest, UpstreamDefaultOptionsIntegration) {
    REQUIRE_INTEGRATION();
    co_await m_loop->co_submit();
    for (const std::string &address : {"8.8.8.8"}) {
        auto upstream_res = create_upstream({address, {}});
        ASSERT_FALSE(upstream_res.has_error())
                << "Failed to generate upstream from address " << address << ": " << upstream_res.error()->str();
        auto err = co_await check_upstream(*upstream_res.value(), address);
        ASSERT_FALSE(err) << *err;
    }
}

struct DeadProxyFailure : UpstreamParamTest<std::tuple<std::string, OutboundProxySettings>> {};
#ifdef _WIN32
// On Windows connections to the dead proxy time out instead of being refused
TEST_P(DeadProxyFailure, DISABLED_FailedExchange) {
#else
TEST_P(DeadProxyFailure, FailedExchange) {
#endif
    co_await m_loop->co_submit();
    auto oproxy = std::make_unique<OutboundProxySettings>(std::get<1>(GetParam()));
    make_upstream_factory(oproxy.get());
    // Target is a dead loopback address; the outbound proxy (127.0.0.1:42) is
    // also dead, so the exchange fails fast with no internet access.
    auto upstream_res = create_upstream({std::get<0>(GetParam()), {}});
    ASSERT_FALSE(upstream_res.has_error()) << upstream_res.error()->str();
    auto err = co_await check_upstream(*upstream_res.value(), std::get<0>(GetParam()));
    ASSERT_TRUE(err.has_value());
}

INSTANTIATE_TEST_SUITE_P(TcpOnlyProxy, DeadProxyFailure,
        ::testing::Combine(::testing::Values("tcp://127.0.0.1:1"),
                ::testing::Values(OutboundProxySettings{OutboundProxyProtocol::HTTP_CONNECT, "127.0.0.1", 42},
                        OutboundProxySettings{OutboundProxyProtocol::HTTPS_CONNECT, "127.0.0.1", 42},
                        OutboundProxySettings{OutboundProxyProtocol::SOCKS4, "127.0.0.1", 42},
                        OutboundProxySettings{OutboundProxyProtocol::SOCKS5, "127.0.0.1", 42})));

INSTANTIATE_TEST_SUITE_P(UdpProxy, DeadProxyFailure,
        ::testing::Combine(::testing::Values("127.0.0.1:1"),
                ::testing::Values(OutboundProxySettings{OutboundProxyProtocol::SOCKS5_UDP, "127.0.0.1", 42})));

} // namespace ag::dns::upstream::test
