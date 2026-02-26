#include <cstring>
#include <gtest/gtest.h>
#include <ldns/ldns.h>
#include <memory>
#include <thread>

#include "common/clock.h"
#include "common/file.h"
#include "common/logger.h"
#include "common/utils.h"
#include "common/socket_address.h"
#include "dns/common/net_consts.h"
#include "dns/proxy/dnsproxy.h"
#include "dns/upstream/upstream_utils.h"

#include "../../upstream/test/test_utils.h"
#include "../dns_forwarder.h"
#include "../dns_forwarder_utils.h"
#include "../svcb.h"

namespace ag::dns::proxy::test {

// Generated with:
// echo | openssl s_client -connect 94.140.14.14:853 -servername dns.adguard-dns.com 2>/dev/null | openssl x509 -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | openssl enc -base64
static constexpr auto ADGUARD_DNS_SPKI = "BF+fS5RPhZQggn38wZ6lqii8lxPNWQPzU2VVVqbLhqM=";
static constexpr auto ZEROSSL_SPKI = "3fLLVjRIWnCqDqIETU2OcnMP7EzmN/Z3Q/jQ8cIaAoc=";

static constexpr auto DNS64_SERVER_ADDR = "2001:4860:4860::6464";
static constexpr auto IPV4_ONLY_HOST = "ipv4only.arpa.";
static constexpr auto CNAME_BLOCKING_HOST = "test2.meshkov.info";

class DnsProxyTest : public ::testing::Test {
protected:
    std::unique_ptr<DnsProxy> m_proxy;

    Logger m_log{"DnsProxyTest"};

    void SetUp() override {
        m_proxy = std::make_unique<DnsProxy>();
        Logger::set_log_level(LogLevel::LOG_LEVEL_TRACE);
    }

    void TearDown() override {
        if (m_proxy) {
            m_proxy->deinit();
        }
    }
};

static DnsProxySettings make_dnsproxy_settings() {
    auto settings = DnsProxySettings::get_default();
    settings.upstreams = {{.address = "8.8.8.8"}};
    settings.adblock_rules_blocking_mode = DnsProxyBlockingMode::REFUSED;
    return settings;
}

static DnsProxySettings make_dnsproxy_settings_with_listeners() {
    auto settings = make_dnsproxy_settings();
    settings.listeners = {
            {.address = "127.0.0.1", .port = 5354, .protocol = utils::TP_UDP},
            {.address = "127.0.0.1", .port = 5355, .protocol = utils::TP_TCP, .persistent = true},
    };
    return settings;
}

static void check_listeners(
        const DnsProxySettings &current, const std::vector<ListenerSettings> &expected) {
    ASSERT_EQ(current.listeners.size(), expected.size());
    for (size_t i = 0; i < expected.size(); ++i) {
        SCOPED_TRACE("listener[" + std::to_string(i) + "]");
        ASSERT_EQ(current.listeners[i].address, expected[i].address);
        ASSERT_EQ(current.listeners[i].port, expected[i].port);
        ASSERT_EQ(current.listeners[i].protocol, expected[i].protocol);
        ASSERT_EQ(current.listeners[i].persistent, expected[i].persistent);
    }
}

static void check_filter_params(
        const DnsProxySettings &current, const DnsFilter::EngineParams &expected) {
    ASSERT_EQ(current.filter_params.filters.size(), expected.filters.size());
    for (size_t i = 0; i < expected.filters.size(); ++i) {
        SCOPED_TRACE("filter[" + std::to_string(i) + "]");
        ASSERT_EQ(current.filter_params.filters[i].id, expected.filters[i].id);
        ASSERT_EQ(current.filter_params.filters[i].data, expected.filters[i].data);
        ASSERT_EQ(current.filter_params.filters[i].in_memory, expected.filters[i].in_memory);
    }
}

static void check_other_settings(
        const DnsProxySettings &current, const DnsProxySettings &expected) {
    ASSERT_EQ(current.blocked_response_ttl_secs, expected.blocked_response_ttl_secs);
    ASSERT_EQ(current.block_ipv6, expected.block_ipv6);
    ASSERT_EQ(current.ipv6_available, expected.ipv6_available);
    ASSERT_EQ(current.dns_cache_size, expected.dns_cache_size);
    ASSERT_EQ(current.adblock_rules_blocking_mode, expected.adblock_rules_blocking_mode);
    ASSERT_EQ(current.hosts_rules_blocking_mode, expected.hosts_rules_blocking_mode);
    ASSERT_EQ(current.optimistic_cache, expected.optimistic_cache);
    ASSERT_EQ(current.enable_dnssec_ok, expected.enable_dnssec_ok);
    ASSERT_EQ(current.enable_retransmission_handling, expected.enable_retransmission_handling);
    ASSERT_EQ(current.block_ech, expected.block_ech);
    ASSERT_EQ(current.block_h3_alpn, expected.block_h3_alpn);
    ASSERT_EQ(current.enable_parallel_upstream_queries, expected.enable_parallel_upstream_queries);
    ASSERT_EQ(current.enable_fallback_on_upstreams_failure, expected.enable_fallback_on_upstreams_failure);
    ASSERT_EQ(current.enable_servfail_on_upstreams_failure, expected.enable_servfail_on_upstreams_failure);
    ASSERT_EQ(current.enable_http3, expected.enable_http3);
    ASSERT_EQ(current.enable_post_quantum_cryptography, expected.enable_post_quantum_cryptography);
    ASSERT_EQ(current.upstreams.size(), expected.upstreams.size());
    for (size_t i = 0; i < expected.upstreams.size(); ++i) {
        SCOPED_TRACE("upstream[" + std::to_string(i) + "]");
        ASSERT_EQ(current.upstreams[i].address, expected.upstreams[i].address);
    }
}

static std::string get_concat_rdfs_as_str(ldns_pkt *pkt) {
    std::string result;
    ldns_rr *rr = ldns_rr_list_rr(ldns_pkt_answer(pkt), 0);
    for (size_t i = 0; i < ldns_rr_rd_count(rr); i++) {
        auto rdf1 = ldns_rr_rdf(rr, i);
        auto rdf_cstr = AllocatedPtr<char>(ldns_rdf2str(rdf1));
        if (i != 0) {
            result += " ";
        }
        result += rdf_cstr.get();
    }
    return result;
}

static ldns_pkt_ptr create_request(
        const std::string &domain, ldns_rr_type type, uint16_t flags, ldns_rr_class cls = LDNS_RR_CLASS_IN) {
    return ldns_pkt_ptr(ldns_pkt_query_new(ldns_dname_new_frm_str(domain.c_str()), type, cls, flags));
}

static void perform_request(
        DnsProxy &proxy, const ldns_pkt_ptr &request, ldns_pkt_ptr &response, DnsMessageInfo *info = nullptr) {
    // Avoid rate limit
    std::this_thread::sleep_for(Millis(100));

    const UniquePtr<ldns_buffer, &ldns_buffer_free> buffer(ldns_buffer_new(REQUEST_BUFFER_INITIAL_CAPACITY));

    ldns_status status = ldns_pkt2buffer_wire(buffer.get(), request.get());
    ASSERT_EQ(status, LDNS_STATUS_OK) << ldns_get_errorstr_by_id(status);

    const auto resp_data = proxy.handle_message_sync(
            {ldns_buffer_at(buffer.get(), 0), ldns_buffer_position(buffer.get())}, info);

    ldns_pkt *resp;
    status = ldns_wire2pkt(&resp, resp_data.data(), resp_data.size());
    ASSERT_EQ(status, LDNS_STATUS_OK) << ldns_get_errorstr_by_id(status);
    response = ldns_pkt_ptr(resp);
}

static AllocatedPtr<char> make_rr_answer_string(ldns_pkt *pkt) {
    return AllocatedPtr<char>{ldns_rdf2str(ldns_rr_rdf(ldns_rr_list_rr(ldns_pkt_answer(pkt), 0), 0))};
}

TEST_F(DnsProxyTest, TestDns64) {
    using namespace std::chrono_literals;

    // Assume default settings don't include a DNS64 upstream
    DnsProxySettings settings = make_dnsproxy_settings();
    settings.dns64 = Dns64Settings{
            .upstreams = {{
                    .address = DNS64_SERVER_ADDR,
            }},
            .max_tries = 5,
            .wait_time = 1s,
    };

    auto [ret, err] = m_proxy->init(settings, {});
    ASSERT_TRUE(ret) << err->str();

    // This is after m_proxy->init() to not crash in m_proxy->deinit()
    if (!test_ipv6_connectivity()) {
        warnlog(m_log, "IPv6 is NOT available, skipping this test");
        return;
    }

    std::this_thread::sleep_for(5s); // Let DNS64 discovery happen

    ldns_pkt_ptr pkt = create_request(IPV4_ONLY_HOST, LDNS_RR_TYPE_AAAA, LDNS_RD);
    ldns_pkt_ptr response;
    ASSERT_NO_FATAL_FAILURE(perform_request(*m_proxy, pkt, response));

    ASSERT_GT(ldns_pkt_ancount(response.get()), 0);
}

TEST_F(DnsProxyTest, TestHttpsRR) {
    // Initialize proxy without filter to get real HTTPS records
    DnsProxySettings settings = make_dnsproxy_settings();
    auto [ret, err] = m_proxy->init(settings, {});
    ASSERT_TRUE(ret) << err->str();

    // Query adguard.com and extract ipv4hint
    ldns_pkt_ptr response;
    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("adguard.com", LDNS_RR_TYPE_HTTPS, LDNS_RD), response));
    ASSERT_EQ(ldns_pkt_get_rcode(response.get()), LDNS_RCODE_NOERROR);
    ASSERT_GT(ldns_pkt_ancount(response.get()), 0);
    
    auto adguard_hints = SvcbHttpsHelpers::get_ip_hints_from_response(response.get());
    ASSERT_FALSE(adguard_hints.empty()) << "No IP hints found in adguard.com HTTPS record";

    // Query cloudflare.com and extract ipv6hint
    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("cloudflare.com", LDNS_RR_TYPE_HTTPS, LDNS_RD), response));
    ASSERT_EQ(ldns_pkt_get_rcode(response.get()), LDNS_RCODE_NOERROR);
    ASSERT_GT(ldns_pkt_ancount(response.get()), 0);
    
    auto cloudflare_hints = SvcbHttpsHelpers::get_ip_hints_from_response(response.get());
    ASSERT_FALSE(cloudflare_hints.empty()) << "No IP hints found in cloudflare.com HTTPS record";

    // Build filter with extracted IP addresses
    std::string filter_rules_ipv4;
    std::string filter_rules_ipv6;
    // Add IPv4 hints from adguard.com
    for (const auto &hint : adguard_hints) {
        if (SocketAddress(hint).is_ipv4()) {
            filter_rules_ipv4 = AG_FMT("{}{}\n", filter_rules_ipv4, hint);
        }
    }
    ASSERT_FALSE(filter_rules_ipv4.empty()) << "No IPv4 hints found in adguard.com HTTPS record";
    // Add IPv6 hints from cloudflare.com
    for (const auto &hint : cloudflare_hints) {
        if (SocketAddress(hint).is_ipv6()) {
            filter_rules_ipv6 = AG_FMT("{}{}\n", filter_rules_ipv6, hint);
        }
    }
    ASSERT_FALSE(filter_rules_ipv6.empty()) << "No IPv6 hints found in cloudflare.com HTTPS record";

    // Reapply proxy settings with the filter
    settings.filter_params = {{{1, AG_FMT("{}{}", filter_rules_ipv4, filter_rules_ipv6), true}}};
    auto [ret2, err2] = m_proxy->reapply_settings(settings, DnsProxy::RO_FILTERS);
    ASSERT_TRUE(ret2) << err2->str();

    //  Verify that requests are now blocked
    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("adguard.com", LDNS_RR_TYPE_HTTPS, LDNS_RD), response));
    ASSERT_EQ(ldns_pkt_get_rcode(response.get()), LDNS_RCODE_REFUSED);

    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("cloudflare.com", LDNS_RR_TYPE_HTTPS, LDNS_RD), response));
    ASSERT_EQ(ldns_pkt_get_rcode(response.get()), LDNS_RCODE_REFUSED);
}

TEST_F(DnsProxyTest, TestResolvedIp) {
    using namespace std::chrono_literals;
    DnsProxySettings settings = make_dnsproxy_settings();
    settings.upstreams = {{
            .address = "tls://dns.adguard-dns.com",
            .resolved_server_ip = Ipv4Address{94, 140, 14, 14},
    }};
    settings.upstream_timeout = 5000ms;
    settings.ipv6_available = false;

    DnsProxyEvents events{.on_certificate_verification = [](CertificateVerificationEvent event) {
                return std::nullopt;
    }};

    auto [ret, err] = m_proxy->init(settings, events);
    ASSERT_TRUE(ret) << err->str();

    ldns_pkt_ptr response;
    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("example.com", LDNS_RR_TYPE_A, LDNS_RD), response));
    ASSERT_GE(ldns_pkt_ancount(response.get()), 1);
    ASSERT_EQ(ldns_pkt_get_rcode(response.get()), LDNS_RCODE_NOERROR);
}


class SPKITest : public ::testing::TestWithParam<std::string> {
protected:
    std::unique_ptr<DnsProxy> m_proxy;
    DnsProxySettings m_settings = make_dnsproxy_settings();
    Logger m_log{"DnsProxyTest"};

    void SetUp() override {
        using namespace std::chrono_literals;
        m_proxy = std::make_unique<DnsProxy>();
        Logger::set_log_level(LogLevel::LOG_LEVEL_TRACE);
        m_settings.upstream_timeout = 5000ms;
        m_settings.ipv6_available = false;
    }

    void TearDown() override {
        if (m_proxy) {
            m_proxy->deinit();
        }
    }
};

static const std::string encrypted_upstreams[] = {
        "quic://dns.adguard-dns.com",
        "tls://dns.adguard-dns.com",
        "https://dns.adguard-dns.com/dns-query"
};

// Disabled since AG servers does not have stable SubjectPublicKeyInfo.
TEST_P(SPKITest, DISABLED_TestSPKI) {
    m_settings.upstreams = {{
        .address = GetParam(),
        .bootstrap = {"1.1.1.1"},
        .resolved_server_ip = Ipv4Address{94, 140, 14, 14},
        .fingerprints = {ADGUARD_DNS_SPKI},
    }};

    DnsProxyEvents events{.on_certificate_verification = [](CertificateVerificationEvent event) {
        return std::nullopt;
    }};

    auto [ret, err] = m_proxy->init(m_settings, events);
    ASSERT_TRUE(ret) << err->str();

    ldns_pkt_ptr response;
    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("example.com", LDNS_RR_TYPE_A, LDNS_RD), response));
    ASSERT_EQ(ldns_pkt_ancount(response.get()), 1);
    ASSERT_EQ(ldns_pkt_get_rcode(response.get()), LDNS_RCODE_NOERROR);
}

// Disabled since AG servers do not have stable SubjectPublicKeyInfo.
TEST_P(SPKITest, DISABLED_MatchSecondFingerprintInChain) {
    m_settings.upstreams = {{
            .address = GetParam(),
            .bootstrap = {"1.1.1.1"},
            .resolved_server_ip = Ipv4Address{94, 140, 14, 14},
            .fingerprints = {ZEROSSL_SPKI},
    }};

    DnsProxyEvents events{.on_certificate_verification = [](CertificateVerificationEvent event) {
        return std::nullopt;
    }};

    auto [ret, err] = m_proxy->init(m_settings, events);
    ASSERT_TRUE(ret) << err->str();

    ldns_pkt_ptr response;
    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("example.com", LDNS_RR_TYPE_A, LDNS_RD), response));
    ASSERT_EQ(ldns_pkt_ancount(response.get()), 1);
    ASSERT_EQ(ldns_pkt_get_rcode(response.get()), LDNS_RCODE_NOERROR);
}

INSTANTIATE_TEST_SUITE_P(SPKITest, SPKITest, testing::ValuesIn(encrypted_upstreams));

TEST_F(DnsProxyTest, TestWrongSPKI) {
    using namespace std::chrono_literals;
    DnsProxySettings settings = make_dnsproxy_settings();
    settings.upstreams = {{
            .address = "https://cloudflare-dns.com/dns-query",
            .bootstrap = {"1.1.1.1"},
            .resolved_server_ip = Ipv4Address{94, 140, 14, 14},
            .fingerprints = {ADGUARD_DNS_SPKI},
    }};
    settings.upstream_timeout = 5000ms,
    settings.ipv6_available = false;
    settings.enable_servfail_on_upstreams_failure = true;

    DnsProxyEvents events{.on_certificate_verification = [](CertificateVerificationEvent event) {
        return std::nullopt;
    }};

    auto [ret, err] = m_proxy->init(settings, events);
    ASSERT_TRUE(ret) << err->str();

    ldns_pkt_ptr response;
    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("example.com", LDNS_RR_TYPE_A, LDNS_RD), response));
    ASSERT_EQ(ldns_pkt_ancount(response.get()), 0);
    ASSERT_EQ(ldns_pkt_get_rcode(response.get()), LDNS_RCODE_SERVFAIL);
}

// Disabled since AG servers does not have stable SubjectPublicKeyInfo.
TEST_F(DnsProxyTest, DISABLED_DnsStampWithHash) {
    using namespace std::chrono_literals;
    DnsProxySettings settings = make_dnsproxy_settings();
    // Stamp's "hashes" field takes another form of hash, generated with:
    // echo | openssl s_client -connect 94.140.14.14:853 -servername dns.adguard-dns.com 2>/dev/null | openssl x509 -outform der | openssl asn1parse -inform der -strparse 4 -noout -out - | openssl dgst -sha256
    settings.upstreams = {{
            .address = "sdns://AwAAAAAAAAAAEDk0LjE0MC4xNC4xNDo4NTMgt62MXPPPq9LPHxpgGSeXXo1flLUZWExquscITUzJnsoTZG5zLmFkZ3VhcmQtZG5zLmNvbQ",
    }};
    settings.upstream_timeout = 5000ms;
    settings.ipv6_available = false;

    DnsProxyEvents events{.on_certificate_verification = [](CertificateVerificationEvent event) {
        return std::nullopt;
    }};

    auto [ret, err] = m_proxy->init(settings, events);
    ASSERT_TRUE(ret) << err->str();

    ldns_pkt_ptr response;
    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("example.com", LDNS_RR_TYPE_A, LDNS_RD), response));
    ASSERT_EQ(ldns_pkt_ancount(response.get()), 1);
    ASSERT_EQ(ldns_pkt_get_rcode(response.get()), LDNS_RCODE_NOERROR);
}

TEST_F(DnsProxyTest, DISABLED_BootstrapOutboundProxy) {
    DnsProxySettings settings = make_dnsproxy_settings();
    settings.upstreams = {{.address = "tls://dns.adguard-dns.com", .bootstrap = {"1.1.1.1"}}};
    settings.outbound_proxy = OutboundProxySettings{
            .protocol = OutboundProxyProtocol::HTTP_CONNECT,
            .address = "localhost",
            .port = 3129,
            .bootstrap = {"127.0.0.53"},
    };
    settings.ipv6_available = false;

    DnsRequestProcessedEvent last_event{};
    DnsProxyEvents events{.on_request_processed = [&last_event](const DnsRequestProcessedEvent &event) {
        last_event = event;
    }};

    auto [ret, err] = m_proxy->init(settings, events);
    ASSERT_TRUE(ret) << err->str();

    ldns_pkt_ptr response;
    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("example.com", LDNS_RR_TYPE_A, LDNS_RD), response));
    ASSERT_EQ(ldns_pkt_ancount(response.get()), 1);
    ASSERT_EQ(ldns_pkt_get_rcode(response.get()), LDNS_RCODE_NOERROR);
}

TEST_F(DnsProxyTest, TestIpv6Blocking) {
    DnsProxySettings settings = make_dnsproxy_settings();
    settings.block_ipv6 = true;
    settings.ipv6_available = false;
    settings.filter_params = {{{1, "cname_blocking_test_filter.txt"}}};

    DnsRequestProcessedEvent last_event{};
    DnsProxyEvents events{.on_request_processed = [&last_event](const DnsRequestProcessedEvent &event) {
        last_event = event;
    }};

    auto [ret, err] = m_proxy->init(settings, events);
    ASSERT_TRUE(ret) << err->str();

    ldns_pkt_ptr pkt = create_request(IPV4_ONLY_HOST, LDNS_RR_TYPE_AAAA, LDNS_RD);
    ldns_pkt_ptr response;
    ASSERT_NO_FATAL_FAILURE(perform_request(*m_proxy, pkt, response));

    ASSERT_EQ(ldns_pkt_ancount(response.get()), 0);
    ASSERT_EQ(ldns_pkt_get_rcode(response.get()), LDNS_RCODE_NOERROR);
    ASSERT_EQ(ldns_pkt_nscount(response.get()), 1);
    ASSERT_EQ(last_event.blocking_reason, DBR_IPV6);

    pkt = create_request("google.com", LDNS_RR_TYPE_AAAA, LDNS_RD);
    response.reset();
    ASSERT_NO_FATAL_FAILURE(perform_request(*m_proxy, pkt, response));

    ASSERT_EQ(ldns_pkt_ancount(response.get()), 0);
    ASSERT_EQ(ldns_pkt_get_rcode(response.get()), LDNS_RCODE_NOERROR);
    ASSERT_EQ(ldns_pkt_nscount(response.get()), 1);
    ASSERT_EQ(last_event.blocking_reason, DBR_IPV6);

    pkt = create_request("example.org", LDNS_RR_TYPE_AAAA, LDNS_RD);
    response.reset();
    ASSERT_NO_FATAL_FAILURE(perform_request(*m_proxy, pkt, response));
    ASSERT_EQ(ldns_pkt_ancount(response.get()), 0);
    ASSERT_EQ(ldns_pkt_get_rcode(response.get()), LDNS_RCODE_REFUSED);
    ASSERT_EQ(last_event.blocking_reason, DBR_QUERY_MATCHED_BY_RULE);

    // Long domain name. With "hostmaster." in SOA record it is longer than 253 characters.
    // https://jira.adguard.com/browse/AG-9026
    pkt = create_request("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa."
                         "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa."
                         "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa."
                         "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.",
            LDNS_RR_TYPE_AAAA, LDNS_RD);
    response.reset();
    ASSERT_NO_FATAL_FAILURE(perform_request(*m_proxy, pkt, response));
    ASSERT_EQ(ldns_pkt_ancount(response.get()), 0);
    ASSERT_EQ(ldns_pkt_nscount(response.get()), 1);
    ASSERT_EQ(ldns_pkt_get_rcode(response.get()), LDNS_RCODE_NOERROR);
    // Check that message is correctly serialized
    using ldns_buffer_ptr = UniquePtr<ldns_buffer, &ldns_buffer_free>;
    ldns_buffer_ptr result(ldns_buffer_new(LDNS_MAX_PACKETLEN));
    ldns_status status = ldns_pkt2buffer_wire(result.get(), response.get());
    ASSERT_EQ(status, LDNS_STATUS_OK);
}

TEST_F(DnsProxyTest, DdrBlocking) {
    DnsProxySettings settings = make_dnsproxy_settings();

    DnsRequestProcessedEvent last_event{};
    DnsProxyEvents events{.on_request_processed = [&last_event](const DnsRequestProcessedEvent &event) {
        last_event = event;
    }};

    auto [ret, err] = m_proxy->init(settings, events);
    ASSERT_TRUE(ret) << err->str();

    ldns_pkt_ptr pkt = create_request("_dns.resolver.arpa", LDNS_RR_TYPE_SVCB, LDNS_RD);
    ldns_pkt_ptr response;
    ASSERT_NO_FATAL_FAILURE(perform_request(*m_proxy, pkt, response));

    ASSERT_EQ(ldns_pkt_ancount(response.get()), 0);
    ASSERT_EQ(ldns_pkt_get_rcode(response.get()), LDNS_RCODE_NOERROR);
    ASSERT_EQ(ldns_pkt_nscount(response.get()), 1);
    ASSERT_EQ(last_event.blocking_reason, DBR_DDR);
}

TEST_F(DnsProxyTest, MozillaDoHBlocking) {
    DnsProxySettings settings = make_dnsproxy_settings();

    DnsRequestProcessedEvent last_event{};
    DnsProxyEvents events{.on_request_processed = [&last_event](const DnsRequestProcessedEvent &event) {
        last_event = event;
    }};

    auto [ret, err] = m_proxy->init(settings, events);
    ASSERT_TRUE(ret) << err->str();

    // Test A query
    ldns_pkt_ptr pkt = create_request("use-application-dns.net", LDNS_RR_TYPE_A, LDNS_RD);
    ldns_pkt_ptr response;
    ASSERT_NO_FATAL_FAILURE(perform_request(*m_proxy, pkt, response));

    ASSERT_EQ(ldns_pkt_ancount(response.get()), 0);
    ASSERT_EQ(ldns_pkt_get_rcode(response.get()), LDNS_RCODE_NXDOMAIN);
    ASSERT_EQ(last_event.blocking_reason, DBR_MOZILLA_DOH_DETECTION);

    // Test AAAA query
    pkt = create_request("use-application-dns.net", LDNS_RR_TYPE_AAAA, LDNS_RD);
    response.reset();
    ASSERT_NO_FATAL_FAILURE(perform_request(*m_proxy, pkt, response));

    ASSERT_EQ(ldns_pkt_ancount(response.get()), 0);
    ASSERT_EQ(ldns_pkt_get_rcode(response.get()), LDNS_RCODE_NXDOMAIN);
    ASSERT_EQ(last_event.blocking_reason, DBR_MOZILLA_DOH_DETECTION);
}

TEST_F(DnsProxyTest, TestCnameBlocking) {
    DnsProxySettings settings = make_dnsproxy_settings();
    settings.filter_params = {{{1, "cname_blocking_test_filter.txt"}}};

    DnsRequestProcessedEvent last_event{};
    DnsProxyEvents events{.on_request_processed = [&last_event](const DnsRequestProcessedEvent &event) {
        last_event = event;
    }};

    auto [ret, err] = m_proxy->init(settings, events);
    ASSERT_TRUE(ret) << err->str();

    ldns_pkt_ptr response;
    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request(CNAME_BLOCKING_HOST, LDNS_RR_TYPE_A, LDNS_RD), response));
    ASSERT_EQ(ldns_pkt_ancount(response.get()), 0);
    ASSERT_EQ(ldns_pkt_get_rcode(response.get()), LDNS_RCODE_REFUSED);
    ASSERT_EQ(last_event.blocking_reason, DBR_CNAME_MATCHED_BY_RULE);
}

TEST_F(DnsProxyTest, test_dnstype_blocking_rule) {
    DnsProxySettings settings = make_dnsproxy_settings();
    settings.filter_params = {{{1, "example.com$dnstype=A|AAAA", true}}};

    DnsRequestProcessedEvent last_event{};
    DnsProxyEvents events{.on_request_processed = [&last_event](const DnsRequestProcessedEvent &event) {
        last_event = event;
    }};

    auto [ret, err] = m_proxy->init(settings, events);
    ASSERT_TRUE(ret) << err->str();

    ldns_pkt_ptr response;
    ASSERT_NO_FATAL_FAILURE(perform_request(*m_proxy, create_request("example.com", LDNS_RR_TYPE_A, LDNS_RD), response));
    ASSERT_EQ(ldns_pkt_ancount(response.get()), 0);
    ASSERT_EQ(ldns_pkt_get_rcode(response.get()), LDNS_RCODE_REFUSED);
    ASSERT_EQ(last_event.rules.size(), 1);
    ASSERT_EQ(last_event.blocking_reason, DBR_QUERY_MATCHED_BY_RULE);
}

TEST_F(DnsProxyTest, TestDnstypeReply) {
    DnsProxySettings settings = make_dnsproxy_settings();
    settings.filter_params = {{{1, "d2iwv1xxkqpmiz.cloudfront.net$dnstype=CNAME", true}}};

    DnsRequestProcessedEvent last_event{};
    DnsProxyEvents events{.on_request_processed = [&last_event](const DnsRequestProcessedEvent &event) {
        last_event = event;
    }};

    auto [ret, err] = m_proxy->init(settings, events);
    ASSERT_TRUE(ret) << err->str();

    ldns_pkt_ptr response;
    ASSERT_NO_FATAL_FAILURE(perform_request(*m_proxy, create_request("www.abc.com", LDNS_RR_TYPE_A, LDNS_RD), response));
    ASSERT_EQ(ldns_pkt_ancount(response.get()), 0);
    ASSERT_EQ(ldns_pkt_get_rcode(response.get()), LDNS_RCODE_REFUSED);
    ASSERT_EQ(last_event.rules.size(), 1);
}

TEST_F(DnsProxyTest, TestDnsrewriteRule) {
    DnsProxySettings settings = make_dnsproxy_settings();
    settings.blocked_response_ttl_secs = 4242;
    settings.filter_params = {{{1,
            "@@example.com$important\n"
            "example.com$dnsrewrite=1.2.3.4\n"
            "example.com$dnsrewrite=NOERROR;A;100.200.200.100\n"
            "example.com$dnsrewrite=NOERROR;MX;42 example.mail\n"
            "@@example.com$dnsrewrite=1.2.3.4\n",
            true}}};

    DnsRequestProcessedEvent last_event{};
    DnsProxyEvents events{.on_request_processed = [&last_event](const DnsRequestProcessedEvent &event) {
        last_event = event;
    }};

    auto [ret, err] = m_proxy->init(settings, events);
    ASSERT_TRUE(ret) << err->str();

    ldns_pkt_ptr response;
    ASSERT_NO_FATAL_FAILURE(perform_request(*m_proxy, create_request("example.com", LDNS_RR_TYPE_A, LDNS_RD), response));
    ASSERT_EQ(last_event.rules.size(), 3);
    ASSERT_EQ(ldns_pkt_get_rcode(response.get()), LDNS_RCODE_NOERROR);
    ASSERT_EQ(ldns_pkt_ancount(response.get()), 1);

    ag::UniquePtr<char, &free> rrstr{ldns_rr2str(ldns_rr_list_rr(ldns_pkt_answer(response.get()), 0))};
    ASSERT_STREQ("example.com.\t4242\tIN\tA\t100.200.200.100\n", rrstr.get());

    ASSERT_NO_FATAL_FAILURE(perform_request(*m_proxy, create_request("example.com", LDNS_RR_TYPE_MX, LDNS_RD), response));
    ASSERT_EQ(last_event.rules.size(), 3);
    ASSERT_EQ(ldns_pkt_get_rcode(response.get()), LDNS_RCODE_NOERROR);
    ASSERT_EQ(ldns_pkt_ancount(response.get()), 1);

    rrstr.reset(ldns_rr2str(ldns_rr_list_rr(ldns_pkt_answer(response.get()), 0)));
    ASSERT_STREQ("example.com.\t4242\tIN\tMX\t42 example.mail.\n", rrstr.get());

    ASSERT_NO_FATAL_FAILURE(perform_request(*m_proxy, create_request("example.com", LDNS_RR_TYPE_AAAA, LDNS_RD), response));
    ASSERT_EQ(last_event.rules.size(), 3);
    ASSERT_EQ(ldns_pkt_get_rcode(response.get()), LDNS_RCODE_NOERROR);
    ASSERT_EQ(ldns_pkt_ancount(response.get()), 0);
}

TEST_F(DnsProxyTest, TestDnsrewriteCname) {
    DnsProxySettings settings = make_dnsproxy_settings();
    settings.filter_params = {{{1, "example.com$dnsrewrite=ietf.org", true}}};

    DnsRequestProcessedEvent last_event{};
    DnsProxyEvents events{.on_request_processed = [&last_event](const DnsRequestProcessedEvent &event) {
        last_event = event;
    }};

    auto [ret, err] = m_proxy->init(settings, events);
    ASSERT_TRUE(ret) << err->str();

    ldns_pkt_ptr response;
    ASSERT_NO_FATAL_FAILURE(perform_request(*m_proxy, create_request("example.com", LDNS_RR_TYPE_A, LDNS_RD), response));
    ASSERT_EQ(last_event.rules.size(), 1);

    ldns_pkt_ptr cname_response;
    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("ietf.org", LDNS_RR_TYPE_A, LDNS_RD), cname_response));

    size_t num = 0;
    for (size_t i = 0; i < ldns_pkt_ancount(cname_response.get()); ++i) {
        const ldns_rr *rr = ldns_rr_list_rr(ldns_pkt_answer(cname_response.get()), i);
        if (ldns_rr_get_type(rr) == LDNS_RR_TYPE_A) {
            ++num;
        }
    }

    ASSERT_EQ(ldns_pkt_ancount(response.get()), num + 1);
    ASSERT_EQ(ldns_pkt_get_rcode(response.get()), LDNS_RCODE_NOERROR);
}

TEST(DnsProxyTest_static, CnameFormatting) {
    const uint8_t packet[] = {0x00, 0x00, 0x81, 0x80, 0x00, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x03, 0x77, 0x77,
            0x77, 0x09, 0x6d, 0x69, 0x63, 0x72, 0x6f, 0x73, 0x6f, 0x66, 0x74, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01,
            0x00, 0x01, 0xc0, 0x0c, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x0c, 0xf5, 0x00, 0x23, 0x03, 0x77, 0x77, 0x77,
            0x09, 0x6d, 0x69, 0x63, 0x72, 0x6f, 0x73, 0x6f, 0x66, 0x74, 0x07, 0x63, 0x6f, 0x6d, 0x2d, 0x63, 0x2d, 0x33,
            0x07, 0x65, 0x64, 0x67, 0x65, 0x6b, 0x65, 0x79, 0x03, 0x6e, 0x65, 0x74, 0x00, 0xc0, 0x2f, 0x00, 0x05, 0x00,
            0x01, 0x00, 0x00, 0x3a, 0x6a, 0x00, 0x37, 0x03, 0x77, 0x77, 0x77, 0x09, 0x6d, 0x69, 0x63, 0x72, 0x6f, 0x73,
            0x6f, 0x66, 0x74, 0x07, 0x63, 0x6f, 0x6d, 0x2d, 0x63, 0x2d, 0x33, 0x07, 0x65, 0x64, 0x67, 0x65, 0x6b, 0x65,
            0x79, 0x03, 0x6e, 0x65, 0x74, 0x0b, 0x67, 0x6c, 0x6f, 0x62, 0x61, 0x6c, 0x72, 0x65, 0x64, 0x69, 0x72, 0x06,
            0x61, 0x6b, 0x61, 0x64, 0x6e, 0x73, 0xc0, 0x4d, 0xc0, 0x5e, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x01, 0x49,
            0x00, 0x19, 0x06, 0x65, 0x31, 0x33, 0x36, 0x37, 0x38, 0x04, 0x64, 0x73, 0x70, 0x62, 0x0a, 0x61, 0x6b, 0x61,
            0x6d, 0x61, 0x69, 0x65, 0x64, 0x67, 0x65, 0xc0, 0x4d, 0xc0, 0xa1, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00,
            0x13, 0x00, 0x04, 0x02, 0x15, 0xc6, 0xe5};
    ldns_pkt *pkt = nullptr;
    ldns_wire2pkt(&pkt, packet, sizeof(packet));
    ASSERT_NE(pkt, nullptr);
    std::string answer = DnsForwarderUtils::rr_list_to_string(ldns_pkt_answer(pkt));
    std::string expected_answer = "CNAME, www.microsoft.com-c-3.edgekey.net.\n"
                                  "CNAME, www.microsoft.com-c-3.edgekey.net.globalredir.akadns.net.\n"
                                  "CNAME, e13678.dspb.akamaiedge.net.\n"
                                  "A, 2.21.198.229\n";
    ASSERT_EQ(answer, expected_answer);
    ldns_pkt_free(pkt);
}

class DnsProxyCacheTest : public ::testing::Test {
protected:
    std::unique_ptr<DnsProxy> m_proxy;
    DnsRequestProcessedEvent m_last_event{};

    Logger m_log{"DnsProxyCacheTest"};

    void TearDown() override {
        if (m_proxy) {
            m_proxy->deinit();
        }
    }

    void SetUp() override {
        Logger::set_log_level(LogLevel::LOG_LEVEL_TRACE);
        DnsProxySettings settings = make_dnsproxy_settings();
        settings.dns_cache_size = 1;
        settings.optimistic_cache = false;

        DnsProxyEvents events{.on_request_processed = [this](DnsRequestProcessedEvent event) {
            m_last_event = std::move(event);
        }};

        m_proxy = std::make_unique<DnsProxy>();
        auto [ret, err] = m_proxy->init(settings, events);
        ASSERT_TRUE(ret) << err->str();
    }
};

TEST_F(DnsProxyCacheTest, CacheWorks) {
    ldns_pkt_ptr pkt = create_request("google.com.", LDNS_RR_TYPE_A, LDNS_RD);
    ldns_pkt_ptr res;
    ASSERT_NO_FATAL_FAILURE(perform_request(*m_proxy, pkt, res));
    ASSERT_FALSE(m_last_event.cache_hit);
    auto first_upstream_id = m_last_event.upstream_id;
    ASSERT_NO_FATAL_FAILURE(perform_request(*m_proxy, pkt, res));
    ASSERT_TRUE(m_last_event.cache_hit);
    ASSERT_TRUE(m_last_event.domain == "google.com.");
    ASSERT_EQ(m_last_event.upstream_id, first_upstream_id);
}

TEST_F(DnsProxyCacheTest, CachedResponseTtlDecreases) {
    ldns_pkt_ptr pkt = create_request("example.org.", LDNS_RR_TYPE_SOA, LDNS_RD);
    ldns_pkt_ptr res;
    ASSERT_NO_FATAL_FAILURE(perform_request(*m_proxy, pkt, res));
    ASSERT_FALSE(m_last_event.cache_hit);
    ASSERT_GT(ldns_pkt_ancount(res.get()), 0);

    const uint32_t ttl = ldns_rr_ttl(ldns_rr_list_rr(ldns_pkt_answer(res.get()), 0));
    ASSERT_GT(ttl, 1);
    SteadyClock::add_time_shift(Secs((ttl / 2) + 1));

    ASSERT_NO_FATAL_FAILURE(perform_request(*m_proxy, pkt, res));
    ASSERT_TRUE(m_last_event.cache_hit);
    const uint32_t cached_ttl = ldns_rr_ttl(ldns_rr_list_rr(ldns_pkt_answer(res.get()), 0));
    ASSERT_LE(cached_ttl, ttl / 2);
}

TEST_F(DnsProxyCacheTest, CachedResponseExpires) {
    ldns_pkt_ptr pkt = create_request("example.org.", LDNS_RR_TYPE_A, LDNS_RD);
    ldns_pkt_ptr res;
    ASSERT_NO_FATAL_FAILURE(perform_request(*m_proxy, pkt, res));
    ASSERT_FALSE(m_last_event.cache_hit);
    ASSERT_GT(ldns_pkt_ancount(res.get()), 0);

    const uint32_t ttl = ldns_rr_ttl(ldns_rr_list_rr(ldns_pkt_answer(res.get()), 0));
    ASSERT_GT(ttl, 0);
    SteadyClock::add_time_shift(Secs(ttl + 1));

    ASSERT_NO_FATAL_FAILURE(perform_request(*m_proxy, pkt, res));
    ASSERT_FALSE(m_last_event.cache_hit);
}

TEST_F(DnsProxyCacheTest, CachedResponseQuestionMatchesRequest) {
    ldns_pkt_ptr pkt = create_request("GoOGLe.CoM", LDNS_RR_TYPE_A, LDNS_RD);
    ldns_pkt_ptr res;
    ASSERT_NO_FATAL_FAILURE(perform_request(*m_proxy, pkt, res));
    ASSERT_FALSE(m_last_event.cache_hit);
    ASSERT_NO_FATAL_FAILURE(perform_request(*m_proxy, pkt, res));
    ASSERT_TRUE(m_last_event.cache_hit);

    ldns_rr *resp_question = ldns_rr_list_rr(ldns_pkt_question(res.get()), 0);
    AllocatedPtr<char> resp_question_domain(ldns_rdf2str(ldns_rr_owner(resp_question)));
    AllocatedPtr<char> req_question_domain(
            ldns_rdf2str(ldns_rr_owner(ldns_rr_list_rr(ldns_pkt_question(pkt.get()), 0))));

    ASSERT_EQ(0, std::strcmp(req_question_domain.get(), resp_question_domain.get()));
    ASSERT_EQ(LDNS_RR_TYPE_A, ldns_rr_get_type(resp_question));
}

TEST_F(DnsProxyCacheTest, CacheSizeIsSet) {
    // Cache size is 1 for this test
    ldns_pkt_ptr res;
    ASSERT_NO_FATAL_FAILURE(perform_request(*m_proxy, create_request("google.com", LDNS_RR_TYPE_A, LDNS_RD), res));
    ASSERT_FALSE(m_last_event.cache_hit);
    ASSERT_NO_FATAL_FAILURE(perform_request(*m_proxy, create_request("yandex.ru", LDNS_RR_TYPE_A, LDNS_RD), res));
    ASSERT_FALSE(m_last_event.cache_hit);
    ASSERT_NO_FATAL_FAILURE(perform_request(*m_proxy, create_request("yandex.ru", LDNS_RR_TYPE_A, LDNS_RD), res));
    ASSERT_TRUE(m_last_event.cache_hit);
    ASSERT_NO_FATAL_FAILURE(perform_request(*m_proxy, create_request("google.com", LDNS_RR_TYPE_A, LDNS_RD), res));
    ASSERT_FALSE(m_last_event.cache_hit);
}

TEST_F(DnsProxyCacheTest, CacheKeyTest) {
    ldns_pkt_ptr res;

    ASSERT_NO_FATAL_FAILURE(perform_request(*m_proxy, create_request("google.com", LDNS_RR_TYPE_A, LDNS_RD), res));
    ASSERT_FALSE(m_last_event.cache_hit);

    // Check case doesn't matter
    ASSERT_NO_FATAL_FAILURE(perform_request(*m_proxy, create_request("GoOgLe.CoM", LDNS_RR_TYPE_A, LDNS_RD), res));
    ASSERT_TRUE(m_last_event.cache_hit);

    // Check class matters
    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("google.com", LDNS_RR_TYPE_A, LDNS_RD, LDNS_RR_CLASS_CH), res));
    ASSERT_FALSE(m_last_event.cache_hit);

    // Check type matters
    ASSERT_NO_FATAL_FAILURE(perform_request(*m_proxy, create_request("google.com", LDNS_RR_TYPE_AAAA, LDNS_RD), res));
    ASSERT_FALSE(m_last_event.cache_hit);

    // Check CD flag matters
    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("google.com", LDNS_RR_TYPE_A, LDNS_RD | LDNS_CD), res));
    ASSERT_FALSE(m_last_event.cache_hit);

    // Check DO flag matters
    ldns_pkt_ptr req = create_request("google.com", LDNS_RR_TYPE_A, LDNS_RD);
    ldns_pkt_set_edns_do(req.get(), true);
    ASSERT_NO_FATAL_FAILURE(perform_request(*m_proxy, req, res));
    ASSERT_FALSE(m_last_event.cache_hit);
}

TEST_F(DnsProxyTest, BlockingModeDefault) {
    DnsProxySettings settings = make_dnsproxy_settings();
    settings.filter_params = {{{1, "blocking_modes_test_filter.txt"}}};

    ASSERT_EQ(DnsProxyBlockingMode::REFUSED, settings.adblock_rules_blocking_mode);
    ASSERT_EQ(DnsProxyBlockingMode::ADDRESS, settings.hosts_rules_blocking_mode);

    auto [ret, err] = m_proxy->init(settings, {});
    ASSERT_TRUE(ret) << err->str();

    ldns_pkt_ptr res;

    ASSERT_NO_FATAL_FAILURE(perform_request(*m_proxy, create_request("adb-style.com", LDNS_RR_TYPE_A, LDNS_RD), res));
    ASSERT_EQ(LDNS_RCODE_REFUSED, ldns_pkt_get_rcode(res.get()));

    ASSERT_NO_FATAL_FAILURE(perform_request(*m_proxy, create_request("adb-style.com", LDNS_RR_TYPE_AAAA, LDNS_RD), res));
    ASSERT_EQ(LDNS_RCODE_REFUSED, ldns_pkt_get_rcode(res.get()));

    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("hosts-style-unspec.com", LDNS_RR_TYPE_A, LDNS_RD), res));
    ASSERT_EQ(LDNS_RCODE_NOERROR, ldns_pkt_get_rcode(res.get()));
    ASSERT_STREQ("0.0.0.0", make_rr_answer_string(res.get()).get());

    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("hosts-style-unspec-6.com", LDNS_RR_TYPE_AAAA, LDNS_RD), res));
    ASSERT_EQ(LDNS_RCODE_NOERROR, ldns_pkt_get_rcode(res.get()));
    ASSERT_STREQ("::", make_rr_answer_string(res.get()).get());

    // Check loopback is equivalent to unspec
    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("hosts-style-loopback.com", LDNS_RR_TYPE_A, LDNS_RD), res));
    ASSERT_EQ(LDNS_RCODE_NOERROR, ldns_pkt_get_rcode(res.get()));
    ASSERT_STREQ("0.0.0.0", make_rr_answer_string(res.get()).get());

    // Check loopback is equivalent to unspec for IPv6
    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("hosts-style-loopback-6.com", LDNS_RR_TYPE_AAAA, LDNS_RD), res));
    ASSERT_EQ(LDNS_RCODE_NOERROR, ldns_pkt_get_rcode(res.get()));
    ASSERT_STREQ("::", make_rr_answer_string(res.get()).get());

    // Check custom IP works
    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("hosts-style-custom.com", LDNS_RR_TYPE_A, LDNS_RD), res));
    ASSERT_EQ(LDNS_RCODE_NOERROR, ldns_pkt_get_rcode(res.get()));
    ASSERT_STREQ("1.2.3.4", make_rr_answer_string(res.get()).get());

    // Check custom IP works for IPv6
    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("hosts-style-custom-6.com", LDNS_RR_TYPE_AAAA, LDNS_RD), res));
    ASSERT_EQ(LDNS_RCODE_NOERROR, ldns_pkt_get_rcode(res.get()));
    ASSERT_STREQ("12::34", make_rr_answer_string(res.get()).get());

    // Check custom (from rule!) IP works
    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("hosts-style-4-and-6.com", LDNS_RR_TYPE_A, LDNS_RD), res));
    ASSERT_EQ(LDNS_RCODE_NOERROR, ldns_pkt_get_rcode(res.get()));
    ASSERT_STREQ("4.5.6.7", make_rr_answer_string(res.get()).get());

    // Check custom (from rule!) IP works for IPv6
    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("hosts-style-4-and-6.com", LDNS_RR_TYPE_AAAA, LDNS_RD), res));
    ASSERT_EQ(LDNS_RCODE_NOERROR, ldns_pkt_get_rcode(res.get()));
    ASSERT_STREQ("45::67", make_rr_answer_string(res.get()).get());
}

TEST_F(DnsProxyTest, BlockingModeNxdomain) {
    DnsProxySettings settings = make_dnsproxy_settings();
    settings.filter_params = {{{1, "blocking_modes_test_filter.txt"}}};
    settings.adblock_rules_blocking_mode = DnsProxyBlockingMode::NXDOMAIN;
    settings.hosts_rules_blocking_mode = DnsProxyBlockingMode::NXDOMAIN;

    auto [ret, err] = m_proxy->init(settings, {});
    ASSERT_TRUE(ret) << err->str();

    ldns_pkt_ptr res;

    ASSERT_NO_FATAL_FAILURE(perform_request(*m_proxy, create_request("adb-style.com", LDNS_RR_TYPE_A, LDNS_RD), res));
    ASSERT_EQ(LDNS_RCODE_NXDOMAIN, ldns_pkt_get_rcode(res.get()));
    ASSERT_EQ(ldns_pkt_nscount(res.get()), 1);

    ASSERT_NO_FATAL_FAILURE(perform_request(*m_proxy, create_request("adb-style.com", LDNS_RR_TYPE_AAAA, LDNS_RD), res));
    ASSERT_EQ(LDNS_RCODE_NXDOMAIN, ldns_pkt_get_rcode(res.get()));
    ASSERT_EQ(ldns_pkt_nscount(res.get()), 1);

    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("hosts-style-unspec.com", LDNS_RR_TYPE_A, LDNS_RD), res));
    ASSERT_EQ(LDNS_RCODE_NXDOMAIN, ldns_pkt_get_rcode(res.get()));
    ASSERT_EQ(ldns_pkt_nscount(res.get()), 1);

    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("hosts-style-unspec-6.com", LDNS_RR_TYPE_AAAA, LDNS_RD), res));
    ASSERT_EQ(LDNS_RCODE_NXDOMAIN, ldns_pkt_get_rcode(res.get()));
    ASSERT_EQ(ldns_pkt_nscount(res.get()), 1);

    // Check loopback is equivalent to unspec
    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("hosts-style-loopback.com", LDNS_RR_TYPE_A, LDNS_RD), res));
    ASSERT_EQ(LDNS_RCODE_NXDOMAIN, ldns_pkt_get_rcode(res.get()));
    ASSERT_EQ(ldns_pkt_nscount(res.get()), 1);

    // Check loopback is equivalent to unspec for IPv6
    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("hosts-style-loopback-6.com", LDNS_RR_TYPE_AAAA, LDNS_RD), res));
    ASSERT_EQ(LDNS_RCODE_NXDOMAIN, ldns_pkt_get_rcode(res.get()));
    ASSERT_EQ(ldns_pkt_nscount(res.get()), 1);

    // Check weird qtype
    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("privacy-policy.truste.com", (ldns_rr_type) 65, LDNS_RD), res));
    ASSERT_EQ(LDNS_RCODE_NXDOMAIN, ldns_pkt_get_rcode(res.get()));
    ASSERT_EQ(ldns_pkt_nscount(res.get()), 1);

    // Check custom IP works
    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("hosts-style-custom.com", LDNS_RR_TYPE_A, LDNS_RD), res));
    ASSERT_EQ(LDNS_RCODE_NOERROR, ldns_pkt_get_rcode(res.get()));
    ASSERT_STREQ("1.2.3.4", make_rr_answer_string(res.get()).get());

    // Check custom IP works for IPv6
    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("hosts-style-custom-6.com", LDNS_RR_TYPE_AAAA, LDNS_RD), res));
    ASSERT_EQ(LDNS_RCODE_NOERROR, ldns_pkt_get_rcode(res.get()));
    ASSERT_STREQ("12::34", make_rr_answer_string(res.get()).get());

    // Check custom (from rule!) IP works
    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("hosts-style-4-and-6.com", LDNS_RR_TYPE_A, LDNS_RD), res));
    ASSERT_EQ(LDNS_RCODE_NOERROR, ldns_pkt_get_rcode(res.get()));
    ASSERT_STREQ("4.5.6.7", make_rr_answer_string(res.get()).get());

    // Check custom (from rule!) IP works for IPv6
    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("hosts-style-4-and-6.com", LDNS_RR_TYPE_AAAA, LDNS_RD), res));
    ASSERT_EQ(LDNS_RCODE_NOERROR, ldns_pkt_get_rcode(res.get()));
    ASSERT_STREQ("45::67", make_rr_answer_string(res.get()).get());
}

TEST_F(DnsProxyTest, BlockingModeRefused) {
    DnsProxySettings settings = make_dnsproxy_settings();
    settings.filter_params = {{{1, "blocking_modes_test_filter.txt"}}};
    settings.adblock_rules_blocking_mode = DnsProxyBlockingMode::REFUSED;
    settings.hosts_rules_blocking_mode = DnsProxyBlockingMode::REFUSED;

    auto [ret, err] = m_proxy->init(settings, {});
    ASSERT_TRUE(ret) << err->str();

    ldns_pkt_ptr res;

    ASSERT_NO_FATAL_FAILURE(perform_request(*m_proxy, create_request("adb-style.com", LDNS_RR_TYPE_A, LDNS_RD), res));
    ASSERT_EQ(LDNS_RCODE_REFUSED, ldns_pkt_get_rcode(res.get()));

    ASSERT_NO_FATAL_FAILURE(perform_request(*m_proxy, create_request("adb-style.com", LDNS_RR_TYPE_AAAA, LDNS_RD), res));
    ASSERT_EQ(LDNS_RCODE_REFUSED, ldns_pkt_get_rcode(res.get()));

    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("hosts-style-unspec.com", LDNS_RR_TYPE_A, LDNS_RD), res));
    ASSERT_EQ(LDNS_RCODE_REFUSED, ldns_pkt_get_rcode(res.get()));

    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("hosts-style-unspec-6.com", LDNS_RR_TYPE_AAAA, LDNS_RD), res));
    ASSERT_EQ(LDNS_RCODE_REFUSED, ldns_pkt_get_rcode(res.get()));

    // Check loopback is equivalent to unspec
    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("hosts-style-loopback.com", LDNS_RR_TYPE_A, LDNS_RD), res));
    ASSERT_EQ(LDNS_RCODE_REFUSED, ldns_pkt_get_rcode(res.get()));

    // Check loopback is equivalent to unspec for IPv6
    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("hosts-style-loopback-6.com", LDNS_RR_TYPE_AAAA, LDNS_RD), res));
    ASSERT_EQ(LDNS_RCODE_REFUSED, ldns_pkt_get_rcode(res.get()));

    // Check HTTPS rrtype
    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("privacy-policy.truste.com", LDNS_RR_TYPE_HTTPS, LDNS_RD), res));
    ASSERT_EQ(LDNS_RCODE_REFUSED, ldns_pkt_get_rcode(res.get()));

    // Check HTTPS rrtype (hosts-style rule with blocking ip)
    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("hosts-style-unspec.com", LDNS_RR_TYPE_HTTPS, LDNS_RD), res));
    ASSERT_EQ(LDNS_RCODE_REFUSED, ldns_pkt_get_rcode(res.get()));

    // Check HTTPS rrtype (hosts-style rule) - request should be bypassed since response processing is triggered
    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("cloudflare.com", LDNS_RR_TYPE_HTTPS, LDNS_RD), res));
    ASSERT_EQ(LDNS_RCODE_NOERROR, ldns_pkt_get_rcode(res.get()));
    ASSERT_EQ(1, ldns_pkt_ancount(res.get()));

    // Check weird qtype
    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("privacy-policy.truste.com", (ldns_rr_type) 67, LDNS_RD), res));
    ASSERT_EQ(LDNS_RCODE_REFUSED, ldns_pkt_get_rcode(res.get()));

    // Check weird qtype (hosts-style rule)
    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("hosts-style-custom.com", (ldns_rr_type) 67, LDNS_RD), res));
    ASSERT_EQ(LDNS_RCODE_NOERROR, ldns_pkt_get_rcode(res.get()));
    ASSERT_EQ(0, ldns_pkt_ancount(res.get()));
    ASSERT_EQ(1, ldns_pkt_nscount(res.get()));

    // Check rule IP works
    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("hosts-style-custom.com", LDNS_RR_TYPE_A, LDNS_RD), res));
    ASSERT_EQ(LDNS_RCODE_NOERROR, ldns_pkt_get_rcode(res.get()));
    ASSERT_STREQ("1.2.3.4", make_rr_answer_string(res.get()).get());

    // Check rule IP works
    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("hosts-style-custom-6.com", LDNS_RR_TYPE_AAAA, LDNS_RD), res));
    ASSERT_EQ(LDNS_RCODE_NOERROR, ldns_pkt_get_rcode(res.get()));
    ASSERT_STREQ("12::34", make_rr_answer_string(res.get()).get());

    // Check rule IP works
    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("hosts-style-4-and-6.com", LDNS_RR_TYPE_A, LDNS_RD), res));
    ASSERT_EQ(LDNS_RCODE_NOERROR, ldns_pkt_get_rcode(res.get()));
    ASSERT_STREQ("4.5.6.7", make_rr_answer_string(res.get()).get());

    // Check rule IP works
    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("hosts-style-4-and-6.com", LDNS_RR_TYPE_AAAA, LDNS_RD), res));
    ASSERT_EQ(LDNS_RCODE_NOERROR, ldns_pkt_get_rcode(res.get()));
    ASSERT_STREQ("45::67", make_rr_answer_string(res.get()).get());
}

TEST_F(DnsProxyTest, BlockingModeUnspecifiedAddress) {
    DnsProxySettings settings = make_dnsproxy_settings();
    settings.filter_params = {{{1, "blocking_modes_test_filter.txt"}}};
    settings.adblock_rules_blocking_mode = DnsProxyBlockingMode::ADDRESS;
    settings.hosts_rules_blocking_mode = DnsProxyBlockingMode::ADDRESS;

    auto [ret, err] = m_proxy->init(settings, {});
    ASSERT_TRUE(ret) << err->str();

    ldns_pkt_ptr res;

    // Check weird qtype
    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("privacy-policy.truste.com", (ldns_rr_type) 65, LDNS_RD), res));
    ASSERT_EQ(LDNS_RCODE_NOERROR, ldns_pkt_get_rcode(res.get()));
    ASSERT_EQ(1, ldns_pkt_nscount(res.get()));

    ASSERT_NO_FATAL_FAILURE(perform_request(*m_proxy, create_request("adb-style.com", LDNS_RR_TYPE_A, LDNS_RD), res));
    ASSERT_EQ(LDNS_RCODE_NOERROR, ldns_pkt_get_rcode(res.get()));
    ASSERT_STREQ("0.0.0.0", make_rr_answer_string(res.get()).get());

    ASSERT_NO_FATAL_FAILURE(perform_request(*m_proxy, create_request("adb-style.com", LDNS_RR_TYPE_AAAA, LDNS_RD), res));
    ASSERT_EQ(LDNS_RCODE_NOERROR, ldns_pkt_get_rcode(res.get()));
    ASSERT_STREQ("::", make_rr_answer_string(res.get()).get());

    // HTTPS request is NOERROR-blocked because there are no non-blocking IPs to put in response
    ASSERT_NO_FATAL_FAILURE(perform_request(*m_proxy, create_request("adb-style.com", LDNS_RR_TYPE_HTTPS, LDNS_RD), res));
    ASSERT_EQ(LDNS_RCODE_NOERROR, ldns_pkt_get_rcode(res.get()));
    ASSERT_EQ(1, ldns_pkt_nscount(res.get()));

    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("hosts-style-unspec.com", LDNS_RR_TYPE_A, LDNS_RD), res));
    ASSERT_EQ(LDNS_RCODE_NOERROR, ldns_pkt_get_rcode(res.get()));
    ASSERT_STREQ("0.0.0.0", make_rr_answer_string(res.get()).get());

    // HTTPS request is NOERROR-blocked because there are no non-blocking IPs to put in response
    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("hosts-style-unspec.com", LDNS_RR_TYPE_HTTPS, LDNS_RD), res));
    ASSERT_EQ(LDNS_RCODE_NOERROR, ldns_pkt_get_rcode(res.get()));
    ASSERT_EQ(1, ldns_pkt_nscount(res.get()));

    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("hosts-style-unspec-6.com", LDNS_RR_TYPE_AAAA, LDNS_RD), res));
    ASSERT_EQ(LDNS_RCODE_NOERROR, ldns_pkt_get_rcode(res.get()));
    ASSERT_STREQ("::", make_rr_answer_string(res.get()).get());

    // HTTPS request is NOERROR-blocked because there are no non-blocking IPs to put in response
    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("hosts-style-unspec-6.com", LDNS_RR_TYPE_HTTPS, LDNS_RD), res));
    ASSERT_EQ(LDNS_RCODE_NOERROR, ldns_pkt_get_rcode(res.get()));
    ASSERT_EQ(1, ldns_pkt_nscount(res.get()));

    // Check loopback is equivalent to unspec
    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("hosts-style-loopback.com", LDNS_RR_TYPE_A, LDNS_RD), res));
    ASSERT_EQ(LDNS_RCODE_NOERROR, ldns_pkt_get_rcode(res.get()));
    ASSERT_STREQ("0.0.0.0", make_rr_answer_string(res.get()).get());

    // HTTPS request is NOERROR-blocked because there are no non-blocking IPs to put in response
    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("hosts-style-loopback.com", LDNS_RR_TYPE_HTTPS, LDNS_RD), res));
    ASSERT_EQ(LDNS_RCODE_NOERROR, ldns_pkt_get_rcode(res.get()));
    ASSERT_EQ(1, ldns_pkt_nscount(res.get()));

    // Check loopback is equivalent to unspec for IPv6
    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("hosts-style-loopback-6.com", LDNS_RR_TYPE_AAAA, LDNS_RD), res));
    ASSERT_EQ(LDNS_RCODE_NOERROR, ldns_pkt_get_rcode(res.get()));
    ASSERT_STREQ("::", make_rr_answer_string(res.get()).get());

    // HTTPS request is NOERROR-blocked because there are no non-blocking IPs to put in response
    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("hosts-style-loopback-6.com", LDNS_RR_TYPE_HTTPS, LDNS_RD), res));
    ASSERT_EQ(LDNS_RCODE_NOERROR, ldns_pkt_get_rcode(res.get()));
    ASSERT_EQ(1, ldns_pkt_nscount(res.get()));

    // Check custom IP works
    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("hosts-style-custom.com", LDNS_RR_TYPE_A, LDNS_RD), res));
    ASSERT_EQ(LDNS_RCODE_NOERROR, ldns_pkt_get_rcode(res.get()));
    ASSERT_STREQ("1.2.3.4", make_rr_answer_string(res.get()).get());

    // Allowed request (to patch response) but non-existent domain
    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("hosts-style-custom.com", LDNS_RR_TYPE_HTTPS, LDNS_RD), res));
    ASSERT_EQ(LDNS_RCODE_NXDOMAIN, ldns_pkt_get_rcode(res.get()));

    // Check custom IP works for IPv6
    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("hosts-style-custom-6.com", LDNS_RR_TYPE_AAAA, LDNS_RD), res));
    ASSERT_EQ(LDNS_RCODE_NOERROR, ldns_pkt_get_rcode(res.get()));
    ASSERT_STREQ("12::34", make_rr_answer_string(res.get()).get());

    // Allowed request (to patch response) but non-existent domain
    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("hosts-style-custom-6.com", LDNS_RR_TYPE_HTTPS, LDNS_RD), res));
    ASSERT_EQ(LDNS_RCODE_NXDOMAIN, ldns_pkt_get_rcode(res.get()));

    // Check custom (from rule!) IP works
    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("hosts-style-4-and-6.com", LDNS_RR_TYPE_A, LDNS_RD), res));
    ASSERT_EQ(LDNS_RCODE_NOERROR, ldns_pkt_get_rcode(res.get()));
    ASSERT_STREQ("4.5.6.7", make_rr_answer_string(res.get()).get());

    // Check custom (from rule!) IP works for IPv6
    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("hosts-style-4-and-6.com", LDNS_RR_TYPE_AAAA, LDNS_RD), res));
    ASSERT_EQ(LDNS_RCODE_NOERROR, ldns_pkt_get_rcode(res.get()));
    ASSERT_STREQ("45::67", make_rr_answer_string(res.get()).get());

    // Allowed request (to patch response) but non-existent domain
    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("hosts-style-4-and-6.com", LDNS_RR_TYPE_HTTPS, LDNS_RD), res));
    ASSERT_EQ(LDNS_RCODE_NXDOMAIN, ldns_pkt_get_rcode(res.get()));

    // Check HTTPS rrtype (hosts-style rule) - request should be bypassed since response processing is triggered
    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("cloudflare.com", LDNS_RR_TYPE_HTTPS, LDNS_RD), res));
    ASSERT_EQ(LDNS_RCODE_NOERROR, ldns_pkt_get_rcode(res.get()));
    ASSERT_EQ(1, ldns_pkt_ancount(res.get()));
    auto hints = SvcbHttpsHelpers::get_ip_hints_from_response(res.get());
    ASSERT_EQ(hints.at(0), "1.3.5.7");
    ASSERT_EQ(hints.at(1), "13::57");
}

TEST_F(DnsProxyTest, BlockingModeCustomAddress) {
    DnsProxySettings settings = make_dnsproxy_settings();
    settings.filter_params = {{{1, "blocking_modes_test_filter.txt"}}};
    settings.adblock_rules_blocking_mode = DnsProxyBlockingMode::ADDRESS;
    settings.hosts_rules_blocking_mode = DnsProxyBlockingMode::ADDRESS;
    settings.custom_blocking_ipv4 = "4.3.2.1";
    settings.custom_blocking_ipv6 = "43::21";

    auto [ret, err] = m_proxy->init(settings, {});
    ASSERT_TRUE(ret) << err->str();

    ldns_pkt_ptr res;

    ASSERT_NO_FATAL_FAILURE(perform_request(*m_proxy, create_request("adb-style.com", LDNS_RR_TYPE_A, LDNS_RD), res));
    ASSERT_EQ(LDNS_RCODE_NOERROR, ldns_pkt_get_rcode(res.get()));
    ASSERT_STREQ("4.3.2.1", make_rr_answer_string(res.get()).get());

    ASSERT_NO_FATAL_FAILURE(perform_request(*m_proxy, create_request("adb-style.com", LDNS_RR_TYPE_AAAA, LDNS_RD), res));
    ASSERT_EQ(LDNS_RCODE_NOERROR, ldns_pkt_get_rcode(res.get()));
    ASSERT_STREQ("43::21", make_rr_answer_string(res.get()).get());

    // Allowed request (to patch response) but non-existent domain
    ASSERT_NO_FATAL_FAILURE(perform_request(*m_proxy, create_request("adb-style.com", LDNS_RR_TYPE_HTTPS, LDNS_RD), res));
    ASSERT_EQ(LDNS_RCODE_NXDOMAIN, ldns_pkt_get_rcode(res.get()));

    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("hosts-style-unspec.com", LDNS_RR_TYPE_A, LDNS_RD), res));
    ASSERT_EQ(LDNS_RCODE_NOERROR, ldns_pkt_get_rcode(res.get()));
    ASSERT_STREQ("4.3.2.1", make_rr_answer_string(res.get()).get());

    // Allowed request (to patch response) but non-existent domain
    ASSERT_NO_FATAL_FAILURE(perform_request(*m_proxy, create_request("hosts-style-unspec.com", LDNS_RR_TYPE_HTTPS, LDNS_RD), res));
    ASSERT_EQ(LDNS_RCODE_NXDOMAIN, ldns_pkt_get_rcode(res.get()));

    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("hosts-style-unspec-6.com", LDNS_RR_TYPE_AAAA, LDNS_RD), res));
    ASSERT_EQ(LDNS_RCODE_NOERROR, ldns_pkt_get_rcode(res.get()));
    ASSERT_STREQ("43::21", make_rr_answer_string(res.get()).get());

    // Allowed request (to patch response) but non-existent domain
    ASSERT_NO_FATAL_FAILURE(perform_request(*m_proxy, create_request("hosts-style-unspec-6.com", LDNS_RR_TYPE_HTTPS, LDNS_RD), res));
    ASSERT_EQ(LDNS_RCODE_NXDOMAIN, ldns_pkt_get_rcode(res.get()));

    // Check loopback is equivalent to unspec
    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("hosts-style-loopback.com", LDNS_RR_TYPE_A, LDNS_RD), res));
    ASSERT_EQ(LDNS_RCODE_NOERROR, ldns_pkt_get_rcode(res.get()));
    ASSERT_STREQ("4.3.2.1", make_rr_answer_string(res.get()).get());

    // Allowed request (to patch response) but non-existent domain
    ASSERT_NO_FATAL_FAILURE(perform_request(*m_proxy, create_request("hosts-style-loopback.com", LDNS_RR_TYPE_HTTPS, LDNS_RD), res));
    ASSERT_EQ(LDNS_RCODE_NXDOMAIN, ldns_pkt_get_rcode(res.get()));

    // Check loopback is equivalent to unspec for IPv6
    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("hosts-style-loopback-6.com", LDNS_RR_TYPE_AAAA, LDNS_RD), res));
    ASSERT_EQ(LDNS_RCODE_NOERROR, ldns_pkt_get_rcode(res.get()));
    ASSERT_STREQ("43::21", make_rr_answer_string(res.get()).get());

    // Allowed request (to patch response) but non-existent domain
    ASSERT_NO_FATAL_FAILURE(perform_request(*m_proxy, create_request("hosts-style-loopback-6.com", LDNS_RR_TYPE_HTTPS, LDNS_RD), res));
    ASSERT_EQ(LDNS_RCODE_NXDOMAIN, ldns_pkt_get_rcode(res.get()));

    // Check custom (from rule!) IP works
    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("hosts-style-custom.com", LDNS_RR_TYPE_A, LDNS_RD), res));
    ASSERT_EQ(LDNS_RCODE_NOERROR, ldns_pkt_get_rcode(res.get()));
    ASSERT_STREQ("1.2.3.4", make_rr_answer_string(res.get()).get());

    // Allowed request (to patch response) but non-existent domain
    ASSERT_NO_FATAL_FAILURE(perform_request(*m_proxy, create_request("hosts-style-custom.com", LDNS_RR_TYPE_HTTPS, LDNS_RD), res));
    ASSERT_EQ(LDNS_RCODE_NXDOMAIN, ldns_pkt_get_rcode(res.get()));

    // Check custom (from rule!) IP works for IPv6
    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("hosts-style-custom-6.com", LDNS_RR_TYPE_AAAA, LDNS_RD), res));
    ASSERT_EQ(LDNS_RCODE_NOERROR, ldns_pkt_get_rcode(res.get()));
    ASSERT_STREQ("12::34", make_rr_answer_string(res.get()).get());

    // Allowed request (to patch response) but non-existent domain
    ASSERT_NO_FATAL_FAILURE(perform_request(*m_proxy, create_request("hosts-style-custom-6.com", LDNS_RR_TYPE_HTTPS, LDNS_RD), res));
    ASSERT_EQ(LDNS_RCODE_NXDOMAIN, ldns_pkt_get_rcode(res.get()));

    // Check custom (from rule!) IP works
    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("hosts-style-4-and-6.com", LDNS_RR_TYPE_A, LDNS_RD), res));
    ASSERT_EQ(LDNS_RCODE_NOERROR, ldns_pkt_get_rcode(res.get()));
    ASSERT_STREQ("4.5.6.7", make_rr_answer_string(res.get()).get());

    // Check custom (from rule!) IP works for IPv6
    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("hosts-style-4-and-6.com", LDNS_RR_TYPE_AAAA, LDNS_RD), res));
    ASSERT_EQ(LDNS_RCODE_NOERROR, ldns_pkt_get_rcode(res.get()));
    ASSERT_STREQ("45::67", make_rr_answer_string(res.get()).get());

    // Allowed request (to patch response) but non-existent domain
    ASSERT_NO_FATAL_FAILURE(perform_request(*m_proxy, create_request("hosts-style-4-and-6.com", LDNS_RR_TYPE_HTTPS, LDNS_RD), res));
    ASSERT_EQ(LDNS_RCODE_NXDOMAIN, ldns_pkt_get_rcode(res.get()));

    // Allowed request (to patch response) but non-existent domain
    ASSERT_NO_FATAL_FAILURE(perform_request(*m_proxy, create_request("crypto.cloudflare.com", LDNS_RR_TYPE_HTTPS, LDNS_RD), res));
    ASSERT_EQ(LDNS_RCODE_NOERROR, ldns_pkt_get_rcode(res.get()));
    auto hints = SvcbHttpsHelpers::get_ip_hints_from_response(res.get());
    ASSERT_EQ(hints.at(0), settings.custom_blocking_ipv4);
    ASSERT_EQ(hints.at(1), settings.custom_blocking_ipv6);
}

TEST_F(DnsProxyTest, HttpsBlockingModeCustomAddressAdblockRule) {
    DnsProxySettings settings = make_dnsproxy_settings();
        settings.filter_params = {{{1, "adguard.com", true}}};
    settings.adblock_rules_blocking_mode = DnsProxyBlockingMode::ADDRESS;
    settings.hosts_rules_blocking_mode = DnsProxyBlockingMode::NXDOMAIN;
    settings.custom_blocking_ipv4 = "4.3.2.1";
    settings.custom_blocking_ipv6 = "43::21";

    auto [ret, err] = m_proxy->init(settings, {});
    ASSERT_TRUE(ret) << err->str();

    ldns_pkt_ptr res;

    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("adguard.com", LDNS_RR_TYPE_HTTPS, LDNS_RD),res));
    ASSERT_EQ(LDNS_RCODE_NOERROR, ldns_pkt_get_rcode(res.get()));
    ASSERT_EQ(1, ldns_pkt_ancount(res.get()));
    auto hints = SvcbHttpsHelpers::get_ip_hints_from_response(res.get());
    ASSERT_EQ(hints.at(0), settings.custom_blocking_ipv4);
    ASSERT_EQ(hints.at(1), settings.custom_blocking_ipv6);
}

TEST_F(DnsProxyTest, HttpsBlockingModeCustomAddressHostsRule) {
    DnsProxySettings settings = make_dnsproxy_settings();
    settings.filter_params = {{{1, "0.0.0.0 adguard.com", true}}};
    settings.adblock_rules_blocking_mode = DnsProxyBlockingMode::NXDOMAIN;
    settings.hosts_rules_blocking_mode = DnsProxyBlockingMode::ADDRESS;
    settings.custom_blocking_ipv4 = "4.3.2.1";
    settings.custom_blocking_ipv6 = "43::21";

    auto [ret, err] = m_proxy->init(settings, {});
    ASSERT_TRUE(ret) << err->str();

    ldns_pkt_ptr res;

    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("adguard.com", LDNS_RR_TYPE_HTTPS, LDNS_RD),res));
    ASSERT_EQ(LDNS_RCODE_NOERROR, ldns_pkt_get_rcode(res.get()));
    ASSERT_EQ(1, ldns_pkt_ancount(res.get()));
    auto hints = SvcbHttpsHelpers::get_ip_hints_from_response(res.get());
    ASSERT_EQ(hints.at(0), settings.custom_blocking_ipv4);
    ASSERT_EQ(hints.at(1), settings.custom_blocking_ipv6);
}

TEST_F(DnsProxyTest, RemoveH3AlpnIfBlocked) {
    DnsProxySettings settings = make_dnsproxy_settings();
    settings.block_h3_alpn = true;

    auto [ret, err] = m_proxy->init(settings, {});
    ASSERT_TRUE(ret) << err->str();

    ldns_pkt_ptr res;

    ASSERT_NO_FATAL_FAILURE(
        perform_request(*m_proxy, create_request("adguard.com", LDNS_RR_TYPE_HTTPS, LDNS_RD), res));
    ASSERT_EQ(LDNS_RCODE_NOERROR, ldns_pkt_get_rcode(res.get()));

    std::string response_str = get_concat_rdfs_as_str(res.get());
    std::cout << response_str << std::endl;

    ASSERT_EQ(response_str.find("alpn=h3"), std::string::npos);
    ASSERT_NE(response_str.find("alpn="), std::string::npos);
    ASSERT_NE(response_str.find("hint"), std::string::npos);
}

TEST_F(DnsProxyTest, RemoveEchIfBlocked) {
    DnsProxySettings settings = make_dnsproxy_settings();
    settings.block_ech = true;

    auto [ret, err] = m_proxy->init(settings, {});
    ASSERT_TRUE(ret) << err->str();

    ldns_pkt_ptr res;

    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("crypto.cloudflare.com", LDNS_RR_TYPE_HTTPS, LDNS_RD),res));
    ASSERT_EQ(LDNS_RCODE_NOERROR, ldns_pkt_get_rcode(res.get()));
    ASSERT_EQ(1, ldns_pkt_ancount(res.get()));

    std::string response_str = get_concat_rdfs_as_str(res.get());
    std::cout << response_str << std::endl;
    ASSERT_EQ(response_str.find("echconfig"), std::string::npos);
    ASSERT_NE(response_str.find("hint"), std::string::npos);
}

TEST_F(DnsProxyTest, HttpsBlockingModeCustomAddressBlockEch) {
    DnsProxySettings settings = make_dnsproxy_settings();
    settings.filter_params = {{{1, "crypto.cloudflare.com", true}}};
    settings.adblock_rules_blocking_mode = DnsProxyBlockingMode::ADDRESS;
    settings.hosts_rules_blocking_mode = DnsProxyBlockingMode::ADDRESS;
    settings.custom_blocking_ipv4 = "4.3.2.1";
    settings.custom_blocking_ipv6 = "43::21";
    settings.block_ech = true;

    auto [ret, err] = m_proxy->init(settings, {});
    ASSERT_TRUE(ret) << err->str();

    ldns_pkt_ptr res;

    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("crypto.cloudflare.com", LDNS_RR_TYPE_HTTPS, LDNS_RD),res));
    ASSERT_EQ(LDNS_RCODE_NOERROR, ldns_pkt_get_rcode(res.get()));
    ASSERT_EQ(1, ldns_pkt_ancount(res.get()));
    auto rdfs = get_concat_rdfs_as_str(res.get());
    auto hints = SvcbHttpsHelpers::get_ip_hints_from_response(res.get());
    ASSERT_EQ(hints.at(0), settings.custom_blocking_ipv4);
    ASSERT_EQ(hints.at(1), settings.custom_blocking_ipv6);
    ASSERT_EQ(rdfs.find("echconfig"), std::string::npos);
}

TEST_F(DnsProxyTest, HttpsBlockingModeCustomAddressDoesntAffectOtherFields) {
    DnsProxySettings settings = make_dnsproxy_settings();
    settings.filter_params = {{{1, "cloudflare-ech.com", true}}};
    settings.adblock_rules_blocking_mode = DnsProxyBlockingMode::ADDRESS;
    settings.hosts_rules_blocking_mode = DnsProxyBlockingMode::ADDRESS;
    settings.custom_blocking_ipv4 = "4.3.2.1";
    settings.custom_blocking_ipv6 = "43::21";

    auto [ret, err] = m_proxy->init(settings, {});
    ASSERT_TRUE(ret) << err->str();

    ldns_pkt_ptr res;

    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("cloudflare-ech.com", LDNS_RR_TYPE_HTTPS, LDNS_RD),res));
    ASSERT_EQ(LDNS_RCODE_NOERROR, ldns_pkt_get_rcode(res.get()));
    ASSERT_EQ(1, ldns_pkt_ancount(res.get()));
    auto rdfs = get_concat_rdfs_as_str(res.get());
    auto hints = SvcbHttpsHelpers::get_ip_hints_from_response(res.get());
    ASSERT_EQ(hints.at(0), settings.custom_blocking_ipv4);
    ASSERT_EQ(hints.at(1), settings.custom_blocking_ipv6);
    ASSERT_NE(rdfs.find("echconfig"), std::string::npos);
}

TEST_F(DnsProxyTest, HttpsBlockingModeCustomAddressIpv4Only) {
    DnsProxySettings settings = make_dnsproxy_settings();
    settings.filter_params = {{{1, "adguard.com", true}}};
    settings.adblock_rules_blocking_mode = DnsProxyBlockingMode::ADDRESS;
    settings.hosts_rules_blocking_mode = DnsProxyBlockingMode::ADDRESS;
    settings.custom_blocking_ipv4 = "4.3.2.1";

    auto [ret, err] = m_proxy->init(settings, {});
    ASSERT_TRUE(ret) << err->str();

    ldns_pkt_ptr res;

    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("adguard.com", LDNS_RR_TYPE_HTTPS, LDNS_RD),res));
    ASSERT_EQ(LDNS_RCODE_NOERROR, ldns_pkt_get_rcode(res.get()));
    ASSERT_EQ(1, ldns_pkt_ancount(res.get()));
    auto hints = SvcbHttpsHelpers::get_ip_hints_from_response(res.get());
    ASSERT_TRUE(hints.size() == 1);
    ASSERT_EQ(hints.at(0), settings.custom_blocking_ipv4);
}

TEST_F(DnsProxyTest, HttpsBlockingModeCustomAddressIpv6Only) {
    DnsProxySettings settings = make_dnsproxy_settings();
    settings.filter_params = {{{1, "adguard.com", true}}};
    settings.adblock_rules_blocking_mode = DnsProxyBlockingMode::ADDRESS;
    settings.hosts_rules_blocking_mode = DnsProxyBlockingMode::ADDRESS;
    settings.custom_blocking_ipv6 = "43::21";

    auto [ret, err] = m_proxy->init(settings, {});
    ASSERT_TRUE(ret) << err->str();

    ldns_pkt_ptr res;

    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("adguard.com", LDNS_RR_TYPE_HTTPS, LDNS_RD),res));
    ASSERT_EQ(LDNS_RCODE_NOERROR, ldns_pkt_get_rcode(res.get()));
    ASSERT_EQ(1, ldns_pkt_ancount(res.get()));
    auto hints = SvcbHttpsHelpers::get_ip_hints_from_response(res.get());
    ASSERT_TRUE(hints.size() == 1);
    ASSERT_EQ(hints.at(0), settings.custom_blocking_ipv6);
}

TEST_F(DnsProxyTest, BlockingModeCustomAddressIpv4Only) {
    DnsProxySettings settings = make_dnsproxy_settings();
    settings.filter_params = {{{1, "blocking_modes_test_filter.txt"}}};
    settings.adblock_rules_blocking_mode = DnsProxyBlockingMode::ADDRESS;
    settings.hosts_rules_blocking_mode = DnsProxyBlockingMode::ADDRESS;
    settings.custom_blocking_ipv4 = "4.3.2.1";

    auto [ret, err] = m_proxy->init(settings, {});
    ASSERT_TRUE(ret) << err->str();

    ldns_pkt_ptr res;

    ASSERT_NO_FATAL_FAILURE(perform_request(*m_proxy, create_request("adb-style.com", LDNS_RR_TYPE_A, LDNS_RD), res));
    ASSERT_EQ(LDNS_RCODE_NOERROR, ldns_pkt_get_rcode(res.get()));
    ASSERT_STREQ("4.3.2.1", make_rr_answer_string(res.get()).get());

    ASSERT_NO_FATAL_FAILURE(perform_request(*m_proxy, create_request("adb-style.com", LDNS_RR_TYPE_AAAA, LDNS_RD), res));
    ASSERT_EQ(LDNS_RCODE_NOERROR, ldns_pkt_get_rcode(res.get()));
    ASSERT_EQ(0, ldns_pkt_ancount(res.get()));
    ASSERT_EQ(1, ldns_pkt_nscount(res.get()));

    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("hosts-style-unspec.com", LDNS_RR_TYPE_A, LDNS_RD), res));
    ASSERT_EQ(LDNS_RCODE_NOERROR, ldns_pkt_get_rcode(res.get()));
    ASSERT_STREQ("4.3.2.1", make_rr_answer_string(res.get()).get());

    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("hosts-style-unspec-6.com", LDNS_RR_TYPE_AAAA, LDNS_RD), res));
    ASSERT_EQ(LDNS_RCODE_NOERROR, ldns_pkt_get_rcode(res.get()));
    ASSERT_EQ(0, ldns_pkt_ancount(res.get()));
    ASSERT_EQ(1, ldns_pkt_nscount(res.get()));

    // Check loopback is equivalent to unspec
    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("hosts-style-loopback.com", LDNS_RR_TYPE_A, LDNS_RD), res));
    ASSERT_EQ(LDNS_RCODE_NOERROR, ldns_pkt_get_rcode(res.get()));
    ASSERT_STREQ("4.3.2.1", make_rr_answer_string(res.get()).get());

    // Check loopback is equivalent to unspec for IPv6
    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("hosts-style-loopback-6.com", LDNS_RR_TYPE_AAAA, LDNS_RD), res));
    ASSERT_EQ(LDNS_RCODE_NOERROR, ldns_pkt_get_rcode(res.get()));
    ASSERT_EQ(0, ldns_pkt_ancount(res.get()));
    ASSERT_EQ(1, ldns_pkt_nscount(res.get()));

    // Check custom (from rule!) IP works
    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("hosts-style-custom.com", LDNS_RR_TYPE_A, LDNS_RD), res));
    ASSERT_EQ(LDNS_RCODE_NOERROR, ldns_pkt_get_rcode(res.get()));
    ASSERT_STREQ("1.2.3.4", make_rr_answer_string(res.get()).get());

    // Check custom (from rule!) IP works for IPv6
    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("hosts-style-custom-6.com", LDNS_RR_TYPE_AAAA, LDNS_RD), res));
    ASSERT_EQ(LDNS_RCODE_NOERROR, ldns_pkt_get_rcode(res.get()));
    ASSERT_STREQ("12::34", make_rr_answer_string(res.get()).get());

    // Check custom (from rule!) IP works
    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("hosts-style-4-and-6.com", LDNS_RR_TYPE_A, LDNS_RD), res));
    ASSERT_EQ(LDNS_RCODE_NOERROR, ldns_pkt_get_rcode(res.get()));
    ASSERT_STREQ("4.5.6.7", make_rr_answer_string(res.get()).get());

    // Check custom (from rule!) IP works for IPv6
    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("hosts-style-4-and-6.com", LDNS_RR_TYPE_AAAA, LDNS_RD), res));
    ASSERT_EQ(LDNS_RCODE_NOERROR, ldns_pkt_get_rcode(res.get()));
    ASSERT_STREQ("45::67", make_rr_answer_string(res.get()).get());
}

TEST_F(DnsProxyTest, BlockingModeCustomAddressIpv6Only) {
    DnsProxySettings settings = make_dnsproxy_settings();
    settings.filter_params = {{{1, "blocking_modes_test_filter.txt"}}};
    settings.adblock_rules_blocking_mode = DnsProxyBlockingMode::ADDRESS;
    settings.hosts_rules_blocking_mode = DnsProxyBlockingMode::ADDRESS;
    settings.custom_blocking_ipv6 = "43::21";

    auto [ret, err] = m_proxy->init(settings, {});
    ASSERT_TRUE(ret) << err->str();

    ldns_pkt_ptr res;

    ASSERT_NO_FATAL_FAILURE(perform_request(*m_proxy, create_request("adb-style.com", LDNS_RR_TYPE_A, LDNS_RD), res));
    ASSERT_EQ(LDNS_RCODE_NOERROR, ldns_pkt_get_rcode(res.get()));
    ASSERT_EQ(0, ldns_pkt_ancount(res.get()));
    ASSERT_EQ(1, ldns_pkt_nscount(res.get()));

    ASSERT_NO_FATAL_FAILURE(perform_request(*m_proxy, create_request("adb-style.com", LDNS_RR_TYPE_AAAA, LDNS_RD), res));
    ASSERT_EQ(LDNS_RCODE_NOERROR, ldns_pkt_get_rcode(res.get()));
    ASSERT_STREQ("43::21", make_rr_answer_string(res.get()).get());

    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("hosts-style-unspec.com", LDNS_RR_TYPE_A, LDNS_RD), res));
    ASSERT_EQ(LDNS_RCODE_NOERROR, ldns_pkt_get_rcode(res.get()));
    ASSERT_EQ(0, ldns_pkt_ancount(res.get()));
    ASSERT_EQ(1, ldns_pkt_nscount(res.get()));

    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("hosts-style-unspec-6.com", LDNS_RR_TYPE_AAAA, LDNS_RD), res));
    ASSERT_EQ(LDNS_RCODE_NOERROR, ldns_pkt_get_rcode(res.get()));
    ASSERT_STREQ("43::21", make_rr_answer_string(res.get()).get());

    // Check loopback is equivalent to unspec
    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("hosts-style-loopback.com", LDNS_RR_TYPE_A, LDNS_RD), res));
    ASSERT_EQ(LDNS_RCODE_NOERROR, ldns_pkt_get_rcode(res.get()));
    ASSERT_EQ(0, ldns_pkt_ancount(res.get()));
    ASSERT_EQ(1, ldns_pkt_nscount(res.get()));

    // Check loopback is equivalent to unspec for IPv6
    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("hosts-style-loopback-6.com", LDNS_RR_TYPE_AAAA, LDNS_RD), res));
    ASSERT_EQ(LDNS_RCODE_NOERROR, ldns_pkt_get_rcode(res.get()));
    ASSERT_STREQ("43::21", make_rr_answer_string(res.get()).get());

    // Check custom (from rule!) IP works
    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("hosts-style-custom.com", LDNS_RR_TYPE_A, LDNS_RD), res));
    ASSERT_EQ(LDNS_RCODE_NOERROR, ldns_pkt_get_rcode(res.get()));
    ASSERT_STREQ("1.2.3.4", make_rr_answer_string(res.get()).get());

    // Check custom (from rule!) IP works for IPv6
    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("hosts-style-custom-6.com", LDNS_RR_TYPE_AAAA, LDNS_RD), res));
    ASSERT_EQ(LDNS_RCODE_NOERROR, ldns_pkt_get_rcode(res.get()));
    ASSERT_STREQ("12::34", make_rr_answer_string(res.get()).get());

    // Check custom (from rule!) IP works
    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("hosts-style-4-and-6.com", LDNS_RR_TYPE_A, LDNS_RD), res));
    ASSERT_EQ(LDNS_RCODE_NOERROR, ldns_pkt_get_rcode(res.get()));
    ASSERT_STREQ("4.5.6.7", make_rr_answer_string(res.get()).get());

    // Check custom (from rule!) IP works for IPv6
    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("hosts-style-4-and-6.com", LDNS_RR_TYPE_AAAA, LDNS_RD), res));
    ASSERT_EQ(LDNS_RCODE_NOERROR, ldns_pkt_get_rcode(res.get()));
    ASSERT_STREQ("45::67", make_rr_answer_string(res.get()).get());
}

TEST_F(DnsProxyTest, CustomBlockingAddressValidation1) {
    DnsProxySettings settings = make_dnsproxy_settings();
    auto [ret, err] = m_proxy->init(settings, {});
    ASSERT_TRUE(ret) << err->str();
}

TEST_F(DnsProxyTest, CustomBlockingAddressValidation2) {
    DnsProxySettings settings = make_dnsproxy_settings();
    settings.custom_blocking_ipv4 = "abracadabra";
    settings.custom_blocking_ipv6 = "::1";
    auto [ret, _] = m_proxy->init(settings, {});
    ASSERT_FALSE(ret);
    m_proxy.reset();
}

TEST_F(DnsProxyTest, CustomBlockingAddressValidation3) {
    DnsProxySettings settings = make_dnsproxy_settings();
    settings.custom_blocking_ipv4 = "127.0.0.1";
    settings.custom_blocking_ipv6 = "abracadabra";
    auto [ret, _] = m_proxy->init(settings, {});
    ASSERT_FALSE(ret);
    m_proxy.reset();
}

TEST_F(DnsProxyTest, CorrectFilterIdsInEvent) {
    DnsProxySettings settings = make_dnsproxy_settings();
    settings.filter_params = {{
            {15, "cname_blocking_test_filter.txt"},
            {-3, "blocking_modes_test_filter.txt"},
    }};

    DnsRequestProcessedEvent last_event{};
    DnsProxyEvents events{.on_request_processed = [&last_event](const DnsRequestProcessedEvent &event) {
        last_event = event;
    }};

    auto [ret, err] = m_proxy->init(settings, events);
    ASSERT_TRUE(ret) << err->str();

    ldns_pkt_ptr res;

    ASSERT_NO_FATAL_FAILURE(perform_request(*m_proxy, create_request(CNAME_BLOCKING_HOST, LDNS_RR_TYPE_A, LDNS_RD), res));
    ASSERT_EQ(1, last_event.filter_list_ids.size());
    ASSERT_EQ(15, last_event.filter_list_ids[0]);

    ASSERT_NO_FATAL_FAILURE(perform_request(*m_proxy, create_request("adb-style.com", LDNS_RR_TYPE_A, LDNS_RD), res));
    ASSERT_EQ(1, last_event.filter_list_ids.size());
    ASSERT_EQ(-3, last_event.filter_list_ids[0]);
}

TEST_F(DnsProxyTest, Whitelisting) {
    DnsProxySettings settings = make_dnsproxy_settings();
    settings.filter_params = {{
            {15, "whitelist_test_filter.txt"},
    }};

    DnsRequestProcessedEvent last_event{};
    DnsProxyEvents events{.on_request_processed = [&last_event](const DnsRequestProcessedEvent &event) {
        last_event = event;
    }};

    auto [ret, err] = m_proxy->init(settings, events);
    ASSERT_TRUE(ret) << err->str();

    ldns_pkt_ptr res;

    ASSERT_NO_FATAL_FAILURE(perform_request(*m_proxy, create_request("example.org", LDNS_RR_TYPE_A, LDNS_RD), res));
    ASSERT_EQ(1, last_event.filter_list_ids.size());
    ASSERT_TRUE(last_event.whitelist);

    ASSERT_NO_FATAL_FAILURE(perform_request(*m_proxy, create_request(CNAME_BLOCKING_HOST, LDNS_RR_TYPE_A, LDNS_RD), res));
    ASSERT_EQ(2, last_event.filter_list_ids.size()); // Whitelisted by both domain and CNAME
    ASSERT_TRUE(last_event.whitelist);

    ASSERT_NO_FATAL_FAILURE(perform_request(*m_proxy, create_request(IPV4_ONLY_HOST, LDNS_RR_TYPE_A, LDNS_RD), res));
    ASSERT_EQ(2, last_event.filter_list_ids.size()); // Whitelisted by domain,
    ASSERT_FALSE(last_event.whitelist); // then blocked by IP, because of $important

    ASSERT_NO_FATAL_FAILURE(perform_request(*m_proxy, create_request("google.com", LDNS_RR_TYPE_A, LDNS_RD), res));
    ASSERT_EQ(0, last_event.filter_list_ids.size()); // Not blocked
    ASSERT_FALSE(last_event.whitelist); // Neither whitelisted

    ASSERT_NO_FATAL_FAILURE(perform_request(*m_proxy, create_request("auth.adguard.com", LDNS_RR_TYPE_A, LDNS_RD), res));
    ASSERT_GT(ldns_pkt_ancount(res.get()), 0);
    ASSERT_EQ(ldns_pkt_get_rcode(res.get()), LDNS_RCODE_NOERROR);
    ASSERT_TRUE(last_event.whitelist);
}

TEST_F(DnsProxyTest, FallbacksIgnoreProxySocks) {
    DnsProxySettings settings = make_dnsproxy_settings();
    settings.fallbacks = settings.upstreams;
    // some nonexistent proxy
    settings.outbound_proxy = {{OutboundProxyProtocol::SOCKS5_UDP, "255.255.255.255", 1}};

    DnsRequestProcessedEvent last_event{};

    auto [ret, err] = m_proxy->init(settings, {});
    ASSERT_TRUE(ret) << err->str();

    ldns_pkt_ptr res;
    ASSERT_NO_FATAL_FAILURE(perform_request(*m_proxy, create_request("example.org", LDNS_RR_TYPE_A, LDNS_RD), res));
    ASSERT_EQ(LDNS_RCODE_NOERROR, ldns_pkt_get_rcode(res.get()));
}

TEST_F(DnsProxyTest, FallbacksIgnoreProxyHttp) {
    DnsProxySettings settings = make_dnsproxy_settings();
    settings.upstreams = {{.address = "tcp://94.140.14.14"}};
    settings.fallbacks = {{.address = "tcp://94.140.14.14"}};
    // some nonexistent proxy
    settings.outbound_proxy = {{OutboundProxyProtocol::HTTP_CONNECT, "255.255.255.255", 1}};

    DnsRequestProcessedEvent last_event{};

    auto [ret, err] = m_proxy->init(settings, {});
    ASSERT_TRUE(ret) << err->str();

    ldns_pkt_ptr res;
    ASSERT_NO_FATAL_FAILURE(perform_request(*m_proxy, create_request("example.org", LDNS_RR_TYPE_A, LDNS_RD), res));
    ASSERT_EQ(LDNS_RCODE_NOERROR, ldns_pkt_get_rcode(res.get()));
}

TEST_F(DnsProxyTest, BadFilterFileDoesNotCrash) {
    DnsProxySettings settings = make_dnsproxy_settings();
    settings.filter_params = {{
            {111, "bad_test_filter.txt"},
    }};
    auto [ret, err] = m_proxy->init(settings, {});
    ASSERT_TRUE(ret) << err->str();
}

TEST_F(DnsProxyTest, RulesLoadFromMemory) {
    DnsProxySettings settings = make_dnsproxy_settings();

    std::string filter_data;
    ag::file::Handle file_handle = ag::file::open("bad_test_filter.txt", ag::file::RDONLY);
    ag::file::for_each_line(
            file_handle,
            [](uint32_t, std::string_view line, void *arg) -> bool {
                auto &s = *(std::string *) arg;
                s += line;
                s += "\r\n";
                return true;
            },
            &filter_data);

    settings.filter_params = {{
            {42, filter_data, true},
    }};
    auto [ret, err] = m_proxy->init(settings, {});
    ASSERT_TRUE(ret) << err->str();
}

TEST_F(DnsProxyTest, IpBlockingRegress) {
    DnsProxySettings settings = make_dnsproxy_settings();
    settings.filter_params = {{
            {15, "crash_regress_test_filter.txt"},
    }};

    DnsRequestProcessedEvent last_event{};
    DnsProxyEvents events{.on_request_processed = [&last_event](const DnsRequestProcessedEvent &event) {
        last_event = event;
    }};

    auto [ret, err] = m_proxy->init(settings, events);
    ASSERT_TRUE(ret) << err->str();

    ldns_pkt_ptr res;

    ASSERT_NO_FATAL_FAILURE(perform_request(*m_proxy, create_request("example.org", LDNS_RR_TYPE_A, LDNS_RD), res));
    ASSERT_EQ(LDNS_RCODE_NOERROR, ldns_pkt_get_rcode(res.get()));

    ASSERT_NO_FATAL_FAILURE(perform_request(*m_proxy, create_request(IPV4_ONLY_HOST, LDNS_RR_TYPE_A, LDNS_RD), res));
    ASSERT_EQ(1, last_event.filter_list_ids.size());
    ASSERT_FALSE(last_event.whitelist);

    ASSERT_NO_FATAL_FAILURE(perform_request(*m_proxy, create_request("dns.adguard.com", LDNS_RR_TYPE_AAAA, LDNS_RD), res));
    ASSERT_EQ(1, last_event.filter_list_ids.size());
    ASSERT_FALSE(last_event.whitelist);
}

TEST_F(DnsProxyTest, Warnings) {
    DnsProxySettings settings = make_dnsproxy_settings();

    settings.filter_params = {{
            {15, "blocking_modes_test_filter.txt"},
    }};
    {
        auto [ret, err_or_warn] = m_proxy->init(settings, {});
        ASSERT_TRUE(ret) << err_or_warn->str();
        ASSERT_FALSE(err_or_warn) << err_or_warn->str();; // No warning
        m_proxy->deinit();
    }

    settings.filter_params.mem_limit = 1;
    {
        auto [ret, err_or_warn] = m_proxy->init(settings, {});
        ASSERT_TRUE(ret) << err_or_warn->str();
        ASSERT_TRUE(err_or_warn); // Mem usage warning
    }
}

TEST_F(DnsProxyTest, OptimisticCache) {
    DnsProxySettings settings = make_dnsproxy_settings();
    settings.optimistic_cache = true;
    settings.dns_cache_size = 100;

    DnsRequestProcessedEvent last_event{};
    DnsProxyEvents events{.on_request_processed = [&last_event](const DnsRequestProcessedEvent &event) {
        last_event = event;
    }};

    auto [ret, err] = m_proxy->init(settings, events);
    ASSERT_TRUE(ret) << err->str();

    ldns_pkt_ptr res;
    ASSERT_NO_FATAL_FAILURE(perform_request(*m_proxy, create_request("example.org", LDNS_RR_TYPE_A, LDNS_RD), res));
    ASSERT_FALSE(last_event.cache_hit);
    ASSERT_EQ(LDNS_RCODE_NOERROR, ldns_pkt_get_rcode(res.get()));
    ASSERT_GT(ldns_pkt_ancount(res.get()), 0);

    uint32_t max_ttl = 0;
    for (int i = 0; i < ldns_pkt_ancount(res.get()); ++i) {
        max_ttl = std::max(max_ttl, ldns_rr_ttl(ldns_rr_list_rr(ldns_pkt_answer(res.get()), i)));
    }

    SteadyClock::add_time_shift(Secs(2 * max_ttl));

    ASSERT_NO_FATAL_FAILURE(perform_request(*m_proxy, create_request("example.org", LDNS_RR_TYPE_A, LDNS_RD), res));
    ASSERT_TRUE(last_event.cache_hit);
    ASSERT_EQ(LDNS_RCODE_NOERROR, ldns_pkt_get_rcode(res.get()));
    ASSERT_GT(ldns_pkt_ancount(res.get()), 0);
    for (int i = 0; i < ldns_pkt_ancount(res.get()); ++i) {
        ASSERT_EQ(1, ldns_rr_ttl(ldns_rr_list_rr(ldns_pkt_answer(res.get()), i)));
    }
}

TEST_F(DnsProxyTest, DnssecSimpleTest) {
    DnsProxySettings settings = make_dnsproxy_settings();
    settings.upstreams[0].address = "1.1.1.1";
    settings.enable_dnssec_ok = true;

    std::vector<std::string> dnssecSupport = {"cloudflare.com", "example.org"};
    std::vector<std::string> dnssecNotSupport = {"adguard.com", "google.com"};
    ldns_enum_rr_type arrOfTypes[] = {LDNS_RR_TYPE_AAAA, LDNS_RR_TYPE_A, LDNS_RR_TYPE_TXT};

    DnsRequestProcessedEvent last_event{};
    DnsProxyEvents events{.on_request_processed = [&last_event](const DnsRequestProcessedEvent &event) {
        last_event = event;
    }};

    auto [ret, err] = m_proxy->init(settings, events);
    ASSERT_TRUE(ret) << err->str();

    for (auto &curAddress : dnssecSupport) {
        for (auto curType : arrOfTypes) {
            ldns_pkt_ptr res;
            ASSERT_NO_FATAL_FAILURE(perform_request(*m_proxy, create_request(curAddress, curType, LDNS_RD), res));
            ASSERT_TRUE(last_event.dnssec);
            ASSERT_EQ(LDNS_RCODE_NOERROR, ldns_pkt_get_rcode(res.get()));
            ASSERT_GT(ldns_pkt_ancount(res.get()), 0);
            // check that RRSIG section does not exist cuz the request haven't DO bit
            ASSERT_TRUE(last_event.answer.find("RRSIG") == std::string::npos);
            auto ptr = ldns_pkt_rr_list_by_type(res.get(), LDNS_RR_TYPE_RRSIG, LDNS_SECTION_ANSWER);
            ASSERT_EQ(nullptr, ptr);
            ldns_rr_list_deep_free(ptr);
        }
    }

    for (auto &curAddress : dnssecNotSupport) {
        for (auto curType : arrOfTypes) {
            ldns_pkt_ptr res;
            ASSERT_NO_FATAL_FAILURE(perform_request(*m_proxy, create_request(curAddress, curType, LDNS_RD), res));
            ASSERT_FALSE(last_event.dnssec);
            ASSERT_EQ(LDNS_RCODE_NOERROR, ldns_pkt_get_rcode(res.get()));
            ASSERT_GT(ldns_pkt_ancount(res.get()), 0);
            // check that RRSIG section does not exist cuz the request haven't DO bit
            ASSERT_TRUE(last_event.answer.find("RRSIG") == std::string::npos);
            auto ptr = ldns_pkt_rr_list_by_type(res.get(), LDNS_RR_TYPE_RRSIG, LDNS_SECTION_ANSWER);
            ASSERT_EQ(nullptr, ptr);
            ldns_rr_list_deep_free(ptr);
        }
    }
}

TEST_F(DnsProxyTest, DnssecRequestWithDOBit) {
    DnsProxySettings settings = make_dnsproxy_settings();
    settings.enable_dnssec_ok = true;

    DnsRequestProcessedEvent last_event{};
    DnsProxyEvents events{.on_request_processed = [&last_event](const DnsRequestProcessedEvent &event) {
        last_event = event;
    }};

    auto [ret, err] = m_proxy->init(settings, events);
    ASSERT_TRUE(ret) << err->str();

    ldns_pkt_ptr res;
    auto req = create_request("cloudflare.com", LDNS_RR_TYPE_A, LDNS_RD);
    ldns_pkt_set_edns_do(req.get(), true);
    ldns_pkt_set_edns_udp_size(req.get(), 4096);
    ASSERT_NO_FATAL_FAILURE(perform_request(*m_proxy, req, res));
    ASSERT_TRUE(last_event.dnssec);
    ASSERT_EQ(LDNS_RCODE_NOERROR, ldns_pkt_get_rcode(res.get()));
    ASSERT_GT(ldns_pkt_ancount(res.get()), 0);
    // check that response not modified
    ASSERT_FALSE(last_event.answer.find("RRSIG") == std::string::npos);
    auto ptr = ldns_pkt_rr_list_by_type(res.get(), LDNS_RR_TYPE_RRSIG, LDNS_SECTION_ANSWER);
    ASSERT_NE(nullptr, ptr);
    ldns_rr_list_deep_free(ptr);
}

TEST_F(DnsProxyTest, DnssecDSRequest) {
    DnsProxySettings settings = make_dnsproxy_settings();
    settings.enable_dnssec_ok = true;

    DnsRequestProcessedEvent last_event{};
    DnsProxyEvents events{.on_request_processed = [&last_event](const DnsRequestProcessedEvent &event) {
        last_event = event;
    }};

    auto [ret, err] = m_proxy->init(settings, events);
    ASSERT_TRUE(ret) << err->str();

    ldns_pkt_ptr res;
    ASSERT_NO_FATAL_FAILURE(perform_request(*m_proxy, create_request("cloudflare.com", LDNS_RR_TYPE_DS, LDNS_RD), res));
    ASSERT_TRUE(last_event.dnssec);
    ASSERT_EQ(LDNS_RCODE_NOERROR, ldns_pkt_get_rcode(res.get()));
    ASSERT_GT(ldns_pkt_ancount(res.get()), 0);
    // check that response was modified cuz DO bit we added
    ASSERT_TRUE(last_event.answer.find("RRSIG") == std::string::npos);
    auto ptr = ldns_pkt_rr_list_by_type(res.get(), LDNS_RR_TYPE_RRSIG, LDNS_SECTION_ANSWER);
    ASSERT_EQ(nullptr, ptr);
    ldns_rr_list_deep_free(ptr);
    // but type of request here is in response
    ptr = ldns_pkt_rr_list_by_type(res.get(), LDNS_RR_TYPE_DS, LDNS_SECTION_ANSWER);
    ASSERT_NE(nullptr, ptr);
    ldns_rr_list_deep_free(ptr);
}

TEST_F(DnsProxyTest, DnssecTheSameQtypeRequest) {
    DnsProxySettings settings = make_dnsproxy_settings();
    // dns.adguard.com answers SERVFAIL
    settings.upstreams = {{.address = "1.1.1.1"}};
    settings.enable_dnssec_ok = true;

    DnsRequestProcessedEvent last_event{};
    DnsProxyEvents events{.on_request_processed = [&last_event](const DnsRequestProcessedEvent &event) {
        last_event = event;
    }};

    auto [ret, err] = m_proxy->init(settings, events);
    ASSERT_TRUE(ret) << err->str();

    ldns_pkt_ptr res;
    ASSERT_NO_FATAL_FAILURE(perform_request(*m_proxy, create_request("a.iana-servers.net", LDNS_RR_TYPE_RRSIG, LDNS_RD), res));
    ASSERT_EQ(LDNS_RCODE_NOERROR, ldns_pkt_get_rcode(res.get()));
    ASSERT_GT(ldns_pkt_ancount(res.get()), 0);
    // check that response not modified
    ASSERT_FALSE(last_event.answer.find("RRSIG") == std::string::npos);
    auto *ptr = ldns_pkt_rr_list_by_type(res.get(), LDNS_RR_TYPE_RRSIG, LDNS_SECTION_ANSWER);
    ASSERT_NE(nullptr, ptr);
    ldns_rr_list_deep_free(ptr);
}

TEST_F(DnsProxyTest, DnssecRegressDoesNotScrubCname) {
    DnsProxySettings settings = make_dnsproxy_settings();
    settings.upstreams = {{.address = "1.1.1.1"}};
    settings.enable_dnssec_ok = true;

    DnsRequestProcessedEvent last_event{};
    DnsProxyEvents events{.on_request_processed = [&last_event](const DnsRequestProcessedEvent &event) {
        last_event = event;
    }};

    auto [ret, err] = m_proxy->init(settings, {});
    ASSERT_TRUE(ret) << err->str();

    ldns_pkt_ptr response;
    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request(CNAME_BLOCKING_HOST, LDNS_RR_TYPE_A, LDNS_RD), response));
    ASSERT_GT(ldns_pkt_ancount(response.get()), 0);
    ASSERT_EQ(ldns_pkt_get_rcode(response.get()), LDNS_RCODE_NOERROR);

    ldns_rr_list *rrs = ldns_pkt_rr_list_by_type(response.get(), LDNS_RR_TYPE_CNAME, LDNS_SECTION_ANSWER);
    ASSERT_NE(rrs, nullptr);
    ASSERT_GT(ldns_rr_list_rr_count(rrs), 0);
    ldns_rr_list_deep_free(rrs);

    rrs = ldns_pkt_rr_list_by_type(response.get(), LDNS_RR_TYPE_A, LDNS_SECTION_ANSWER);
    ASSERT_NE(rrs, nullptr);
    ASSERT_GT(ldns_rr_list_rr_count(rrs), 0);
    ldns_rr_list_deep_free(rrs);
}

TEST_F(DnsProxyTest, DnssecAuthoritySection) {
    DnsProxySettings settings = make_dnsproxy_settings();
    settings.enable_dnssec_ok = true;

    DnsRequestProcessedEvent last_event{};
    DnsProxyEvents events{.on_request_processed = [&last_event](const DnsRequestProcessedEvent &event) {
        last_event = event;
    }};

    static const ldns_enum_rr_type SPECIAL_TYPES_DNSSEC_LOG_LOGIC[]
            = {LDNS_RR_TYPE_DS, LDNS_RR_TYPE_DNSKEY, LDNS_RR_TYPE_NSEC, LDNS_RR_TYPE_NSEC3, LDNS_RR_TYPE_RRSIG};

    auto [ret, err] = m_proxy->init(settings, events);
    ASSERT_TRUE(ret) << err->str();

    for (auto cur : SPECIAL_TYPES_DNSSEC_LOG_LOGIC) {
        ldns_pkt_ptr res;
        ASSERT_NO_FATAL_FAILURE(
                perform_request(*m_proxy, create_request("actuallythissitedoesnotexist.fuu", cur, LDNS_RD), res));
        ASSERT_EQ(LDNS_RCODE_NXDOMAIN, ldns_pkt_get_rcode(res.get()));
        auto ptr = ldns_pkt_rr_list_by_type(res.get(), LDNS_RR_TYPE_SIG, LDNS_SECTION_ANSWER);
        ASSERT_EQ(nullptr, ptr);
        ldns_rr_list_deep_free(ptr);
        for (auto cur : SPECIAL_TYPES_DNSSEC_LOG_LOGIC) {
            auto ptr = ldns_pkt_rr_list_by_type(res.get(), cur, LDNS_SECTION_AUTHORITY);
            ASSERT_EQ(nullptr, ptr);
            ldns_rr_list_deep_free(ptr);
        }
    }
}

TEST_F(DnsProxyTest, FallbackFilterWorksAndDefaultsAreCorrect) {
    static constexpr int32_t UPSTREAM_ID = 42;
    static constexpr int32_t FALLBACK_ID = 4242;
    DnsProxySettings settings = make_dnsproxy_settings();
    settings.upstreams = {{.address = "8.8.8.8", .id = UPSTREAM_ID}};
    settings.fallbacks = {{.address = "8.8.8.8", .id = FALLBACK_ID}};
    DnsRequestProcessedEvent last_event{};
    DnsProxyEvents events{.on_request_processed = [&last_event](const DnsRequestProcessedEvent &event) {
        last_event = event;
    }};
    auto [ret, err] = m_proxy->init(settings, events);
    ASSERT_TRUE(ret) << err->str();
    for (const std::string &host : {
                 "epdg.epc.aptg.com.tw",
                 "epdg.epc.att.net",
                 "epdg.mobileone.net.sg",
                 "primgw.vowifina.spcsdns.net",
                 "swu-loopback-epdg.qualcomm.com",
                 "vowifi.jio.com",
                 "weconnect.globe.com.ph",
                 "wlan.three.com.hk",
                 "wo.vzwwo.com",
                 "epdg.epc.mncXXX.mccYYY.pub.3gppnetwork.org",
                 "ss.epdg.epc.mncXXX.mccYYY.pub.3gppnetwork.org",
         }) {
        ldns_pkt_ptr res;
        ASSERT_NO_FATAL_FAILURE(perform_request(*m_proxy, create_request(host, LDNS_RR_TYPE_A, LDNS_RD), res));
        ASSERT_TRUE(last_event.upstream_id.has_value()) << last_event.error;
        ASSERT_EQ(FALLBACK_ID, *last_event.upstream_id) << last_event.domain;
    }
    for (const std::string &host : {
                 "a.epdg.epc.aptg.com.tw",
                 "b.epdg.epc.att.net",
                 "c.epdg.mobileone.net.sg",
                 "d.primgw.vowifina.spcsdns.net",
                 "e.swu-loopback-epdg.qualcomm.com",
                 "f.vowifi.jio.com",
                 "g.weconnect.globe.com.ph",
                 "h.wlan.three.com.hk",
                 "i.wo.vzwwo.com",
                 "pub.3gppnetwork.org",
                 "xyz.pub.3gppnetwork.org",
         }) {
        ldns_pkt_ptr res;
        ASSERT_NO_FATAL_FAILURE(perform_request(*m_proxy, create_request(host, LDNS_RR_TYPE_A, LDNS_RD), res));
        ASSERT_TRUE(last_event.upstream_id.has_value()) << last_event.error;
        ASSERT_EQ(UPSTREAM_ID, *last_event.upstream_id) << last_event.domain;
    }
}

// TestF(DnsProxyTest, FallbackDomainsBad) {
//     ag::dnsproxy_settings settings = make_dnsproxy_settings();
//     for (const std::string &pattern : {"...",
//                                        "*",
//                                        "***",
//                                        "@@||example.org$important",
//                                        }) {
//         settings.fallback_domains = {pattern};
//         auto [ret, err] = m_proxy->init(settings, {});
//         ASSERT_FALSE(ret) << pattern;
//         ASSERT_TRUE(err) << pattern;
//         ASSERT_TRUE(strstr(err->c_str(), pattern.c_str())) << err->str();
//     }
// }

TEST_F(DnsProxyTest, FallbackDomainsGood) {
    DnsProxySettings settings = make_dnsproxy_settings();
    for (const std::string &pattern : {
                 "*.example.org",
                 "*exampl",
                 "exa*mp*l.com",
                 "mygateway",
                 "*.local",
                 "*.company.local",
         }) {
        settings.fallback_domains = {pattern};
        auto [ret, err] = m_proxy->init(settings, {});
        ASSERT_TRUE(ret) << pattern;
        ASSERT_FALSE(err) << pattern;
        m_proxy->deinit();
    }
    m_proxy.reset();
}

TEST_F(DnsProxyTest, DenyallowRulesDoNotMatchIpAddresses) {
    DnsProxySettings settings = make_dnsproxy_settings();
    settings.upstreams = {{.address = "1.1.1.1"}};
    settings.adblock_rules_blocking_mode = DnsProxyBlockingMode::REFUSED;
    settings.hosts_rules_blocking_mode = DnsProxyBlockingMode::REFUSED;
    settings.filter_params.filters = {
            {
                    .id = 1,
                    .data = "192.0.0.170\n"
                            "192.0.0.171\n"
                            "*$denyallow=arpa|org\n",
                    .in_memory = true,
            },
    };

    DnsRequestProcessedEvent last_event{};
    DnsProxyEvents events{.on_request_processed = [&last_event](const DnsRequestProcessedEvent &event) {
        last_event = event;
    }};

    auto [ret, err] = m_proxy->init(settings, {});
    ASSERT_TRUE(ret) << err->str();

    ldns_pkt_ptr response;

    // Blocked by `*$denyallow=arpa|org`
    perform_request(*m_proxy, create_request("example.com", LDNS_RR_TYPE_A, LDNS_RD), response);
    ASSERT_EQ(ldns_pkt_get_rcode(response.get()), LDNS_RCODE_REFUSED);

    // Blocked by IP
    perform_request(*m_proxy, create_request("ipv4only.arpa", LDNS_RR_TYPE_A, LDNS_RD), response);
    ASSERT_EQ(ldns_pkt_get_rcode(response.get()), LDNS_RCODE_REFUSED);

    // Without a special case that IPs must not match $denyallow rules,
    // this would be blocked, because example.org's IP is not in denyallow domains.
    perform_request(*m_proxy, create_request("example.org", LDNS_RR_TYPE_A, LDNS_RD), response);
    ASSERT_GT(ldns_pkt_ancount(response.get()), 0);
    ASSERT_EQ(ldns_pkt_get_rcode(response.get()), LDNS_RCODE_NOERROR);
}

TEST_F(DnsProxyTest, TransparentRequest) {
    auto settings = make_dnsproxy_settings();
    std::optional<DnsRequestProcessedEvent> last_event{};
    DnsProxyEvents events{.on_request_processed = [&last_event](const DnsRequestProcessedEvent &event) {
        last_event = event;
    }};
    auto [ret, err] = m_proxy->init(settings, events);
    ASSERT_TRUE(ret) << err->str();

    auto req = create_request("example.org", LDNS_RR_TYPE_A, LDNS_RD);
    DnsMessageInfo info{.transparent = true};

    uint8_t *msg_data;
    size_t msg_size;
    ASSERT_EQ(LDNS_STATUS_OK, ldns_pkt2wire(&msg_data, req.get(), &msg_size));
    ag::AllocatedPtr<uint8_t> msg_guard{msg_data};

    auto hmsg_result = m_proxy->handle_message_sync({msg_data, msg_size}, &info);

    ASSERT_FALSE(last_event.has_value());

    ldns_pkt *result_pkt;
    ASSERT_EQ(LDNS_STATUS_OK, ldns_wire2pkt(&result_pkt, hmsg_result.data(), hmsg_result.size()));
    ag::UniquePtr<ldns_pkt, &ldns_pkt_free> result_guard{result_pkt};

    ASSERT_FALSE(ldns_pkt_qr(result_pkt));

    result_guard = create_request("example.org", LDNS_RR_TYPE_A, LDNS_RD);
    result_pkt = result_guard.get();

    ldns_pkt_set_qr(result_pkt, true);

    ldns_rr *rr_a;
    ASSERT_EQ(LDNS_STATUS_OK, ldns_rr_new_frm_str(&rr_a, "example.org.            6241    IN      A       93.184.216.34", 100, nullptr, nullptr));
    ldns_pkt_push_rr(result_pkt, LDNS_SECTION_ANSWER, rr_a);
    ASSERT_EQ(LDNS_STATUS_OK, ldns_pkt2wire(&msg_data, result_pkt, &msg_size));
    msg_guard.reset(msg_data);

    hmsg_result = m_proxy->handle_message_sync({msg_data, msg_size}, &info);

    ASSERT_TRUE(last_event.has_value());
    ASSERT_EQ(LDNS_STATUS_OK, ldns_wire2pkt(&result_pkt, hmsg_result.data(), hmsg_result.size()));
    result_guard.reset(result_pkt);

    ASSERT_TRUE(ldns_pkt_qr(result_pkt));
    ASSERT_EQ(1, ldns_pkt_ancount(result_pkt));
}

TEST_F(DnsProxyTest, FallbackDomainWorksWhenFallbackOnUpstreamsFailureDisabled) {
    DnsProxySettings settings = make_dnsproxy_settings();
    settings.upstreams = {{.address = "1.2.3.4"}};
    settings.fallbacks = {{.address = "8.8.8.8"}};
    settings.fallback_domains = {"*.example.org"};
    settings.enable_fallback_on_upstreams_failure = false;
    DnsProxy proxy;
    auto [ret, err] = proxy.init(settings, {});
    ASSERT_TRUE(ret);
    ldns_pkt_ptr request = create_request("www.example.org", LDNS_RR_TYPE_A, LDNS_RD);
    ldns_pkt_ptr response;
    perform_request(proxy, request, response);

    ASSERT_EQ(LDNS_RCODE_NOERROR, ldns_pkt_get_rcode(response.get()));
    proxy.deinit();
}

TEST_F(DnsProxyTest, DoNotCrashOnPacketWithoutQuestion) {
    DnsProxySettings settings = make_dnsproxy_settings();
    settings.upstreams = {{.address = "1.2.3.4"}};
    settings.fallbacks = {{.address = "8.8.8.8"}};
    settings.fallback_domains = {"*.example.org"};
    settings.enable_fallback_on_upstreams_failure = false;
    DnsProxy proxy;
    auto [ret, err] = proxy.init(settings, {});
    ASSERT_TRUE(ret);
    ldns_pkt_ptr request{ldns_pkt_new()};
    ldns_pkt_ptr response;
    perform_request(proxy, request, response);

    ASSERT_EQ(LDNS_RCODE_SERVFAIL, ldns_pkt_get_rcode(response.get()));
    proxy.deinit();
}

TEST_F(DnsProxyTest, TransparentModeAllowsUnblockedDomains) {
    auto settings = make_dnsproxy_settings();
    settings.filter_params = {{{1, "||blocked-test-domain.example^\n", true}}};

    DnsRequestProcessedEvent last_event{};
    DnsProxyEvents events{.on_request_processed = [&last_event](const DnsRequestProcessedEvent &event) {
        last_event = event;
    }};

    auto [ret, err] = m_proxy->init(settings, events);
    ASSERT_TRUE(ret) << err->str();

    uint16_t query_id = ldns_pkt_id(create_request("google.com", LDNS_RR_TYPE_A, LDNS_RD).get());

    // Captured DNS response for google.com
    // Real response from 8.8.8.8 (124 bytes)
    // Contains: 6 A records for google.com
    static const uint8_t CAPTURED_GOOGLE_RESPONSE[] = {0x00, 0x00, 0x81, 0x80, 0x00, 0x01, 0x00, 0x06, 0x00, 0x00, 0x00,
            0x00, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0,
            0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x04, 0x8e, 0xfa, 0x8c, 0x65, 0xc0, 0x0c, 0x00,
            0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x04, 0x8e, 0xfa, 0x8c, 0x71, 0xc0, 0x0c, 0x00, 0x01, 0x00,
            0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x04, 0x8e, 0xfa, 0x8c, 0x8a, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00,
            0x00, 0x00, 0x0c, 0x00, 0x04, 0x8e, 0xfa, 0x8c, 0x64, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00,
            0x0c, 0x00, 0x04, 0x8e, 0xfa, 0x8c, 0x8b, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00,
            0x04, 0x8e, 0xfa, 0x8c, 0x66};

    Uint8Vector response_copy(CAPTURED_GOOGLE_RESPONSE, CAPTURED_GOOGLE_RESPONSE + sizeof(CAPTURED_GOOGLE_RESPONSE));

    response_copy[0] = (query_id >> 8) & 0xFF;
    response_copy[1] = query_id & 0xFF;

    DnsMessageInfo response_info{.transparent = true};
    Uint8Vector filtered_response =
            m_proxy->handle_message_sync({response_copy.data(), response_copy.size()}, &response_info);
    ASSERT_FALSE(filtered_response.empty());

    ldns_pkt *filtered_pkt;
    ASSERT_EQ(LDNS_STATUS_OK, ldns_wire2pkt(&filtered_pkt, filtered_response.data(), filtered_response.size()));
    ag::UniquePtr<ldns_pkt, &ldns_pkt_free> filtered_guard{filtered_pkt};

    ASSERT_EQ(ldns_pkt_id(filtered_pkt), query_id);
    ASSERT_NE(ldns_pkt_get_rcode(filtered_pkt), LDNS_RCODE_REFUSED) << "Response was incorrectly blocked";
    ASSERT_EQ(last_event.domain, "google.com.");
}

TEST_F(DnsProxyTest, TransparentModeBlocksDomains) {
    auto settings = make_dnsproxy_settings();
    settings.filter_params = {{{1, "||blocked-test-domain.example^\n", true}}};

    DnsRequestProcessedEvent last_event{};
    DnsProxyEvents events{.on_request_processed = [&last_event](const DnsRequestProcessedEvent &event) {
        last_event = event;
    }};

    auto [ret, err] = m_proxy->init(settings, events);
    ASSERT_TRUE(ret) << err->str();

    ldns_pkt_ptr query = create_request("blocked-test-domain.example", LDNS_RR_TYPE_A, LDNS_RD);

    uint8_t *query_wire;
    size_t query_size;
    ASSERT_EQ(LDNS_STATUS_OK, ldns_pkt2wire(&query_wire, query.get(), &query_size));
    ag::AllocatedPtr<uint8_t> query_guard{query_wire};

    DnsMessageInfo info{.transparent = true};
    Uint8Vector processed_query = m_proxy->handle_message_sync({query_wire, query_size}, &info);

    ASSERT_FALSE(processed_query.empty());

    ldns_pkt *processed_pkt;
    ASSERT_EQ(LDNS_STATUS_OK, ldns_wire2pkt(&processed_pkt, processed_query.data(), processed_query.size()));
    ag::UniquePtr<ldns_pkt, &ldns_pkt_free> processed_guard{processed_pkt};

    ASSERT_TRUE(ldns_pkt_qr(processed_pkt)) << "Query was not blocked";
    ASSERT_EQ(ldns_pkt_get_rcode(processed_pkt), LDNS_RCODE_REFUSED);
    ASSERT_EQ(last_event.blocking_reason, DBR_QUERY_MATCHED_BY_RULE);
}

namespace {
// Shared constants for transparent mode CNAME filtering tests
constexpr auto TRANSPARENT_CNAME_TEST_DOMAIN = "www.github.com";

// Captured DNS response for www.github.com with CNAME
// Real response from 8.8.8.8 (62 bytes)
// Contains: www.github.com CNAME github.com + A record
constexpr uint8_t CAPTURED_DNS_RESPONSE_WITH_CNAME[] = {0x00, 0x00, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00,
        0x00, 0x00, 0x03, 0x77, 0x77, 0x77, 0x06, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x03, 0x63, 0x6f, 0x6d, 0x00,
        0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x0f, 0x00, 0x02, 0xc0, 0x10,
        0xc0, 0x10, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 0x14, 0x1a, 0x9c, 0xd7};
} // namespace

TEST_F(DnsProxyTest, TransparentModeWhitelistPreventsBlockingByCname) {

    auto settings = make_dnsproxy_settings();
    settings.filter_params = {{{1,
            "|github.com^\n"          // Block CNAME target (exact match only)
            "@@||www.github.com^|\n", // Whitelist original domain
            true}}};

    DnsRequestProcessedEvent last_event{};
    DnsProxyEvents events{.on_request_processed = [&last_event](const DnsRequestProcessedEvent &event) {
        last_event = event;
    }};

    auto [ret, err] = m_proxy->init(settings, events);
    ASSERT_TRUE(ret) << err->str();

    ldns_pkt_ptr query = create_request(TRANSPARENT_CNAME_TEST_DOMAIN, LDNS_RR_TYPE_A, LDNS_RD);
    uint16_t query_id = ldns_pkt_id(query.get());

    Uint8Vector response_copy(CAPTURED_DNS_RESPONSE_WITH_CNAME,
            CAPTURED_DNS_RESPONSE_WITH_CNAME + sizeof(CAPTURED_DNS_RESPONSE_WITH_CNAME));

    response_copy[0] = (query_id >> 8) & 0xFF;
    response_copy[1] = query_id & 0xFF;

    DnsMessageInfo response_info{.transparent = true};
    Uint8Vector filtered_response =
            m_proxy->handle_message_sync({response_copy.data(), response_copy.size()}, &response_info);
    ASSERT_FALSE(filtered_response.empty());

    ldns_pkt *filtered_pkt;
    ASSERT_EQ(LDNS_STATUS_OK, ldns_wire2pkt(&filtered_pkt, filtered_response.data(), filtered_response.size()));
    ag::UniquePtr<ldns_pkt, &ldns_pkt_free> filtered_guard{filtered_pkt};

    ASSERT_EQ(ldns_pkt_id(filtered_pkt), query_id);
    ASSERT_NE(ldns_pkt_get_rcode(filtered_pkt), LDNS_RCODE_REFUSED)
            << "Whitelist for original domain should prevent CNAME blocking";
    ASSERT_EQ(last_event.domain, std::string(TRANSPARENT_CNAME_TEST_DOMAIN) + ".");
}

TEST_F(DnsProxyTest, TransparentModeImportantOverridesWhitelist) {
    auto settings = make_dnsproxy_settings();
    settings.filter_params = {{{1,
            "|github.com^$important\n"
            "@@||www.github.com^|\n",
            true}}};

    DnsRequestProcessedEvent last_event{};
    DnsProxyEvents events{.on_request_processed = [&last_event](const DnsRequestProcessedEvent &event) {
        last_event = event;
    }};

    auto [ret, err] = m_proxy->init(settings, events);
    ASSERT_TRUE(ret) << err->str();

    ldns_pkt_ptr query = create_request(TRANSPARENT_CNAME_TEST_DOMAIN, LDNS_RR_TYPE_A, LDNS_RD);
    uint16_t query_id = ldns_pkt_id(query.get());

    Uint8Vector response_copy(CAPTURED_DNS_RESPONSE_WITH_CNAME,
            CAPTURED_DNS_RESPONSE_WITH_CNAME + sizeof(CAPTURED_DNS_RESPONSE_WITH_CNAME));

    response_copy[0] = (query_id >> 8) & 0xFF;
    response_copy[1] = query_id & 0xFF;

    DnsMessageInfo response_info{.transparent = true};
    Uint8Vector filtered_response =
            m_proxy->handle_message_sync({response_copy.data(), response_copy.size()}, &response_info);
    ASSERT_FALSE(filtered_response.empty());

    ldns_pkt *filtered_pkt;
    ASSERT_EQ(LDNS_STATUS_OK, ldns_wire2pkt(&filtered_pkt, filtered_response.data(), filtered_response.size()));
    ag::UniquePtr<ldns_pkt, &ldns_pkt_free> filtered_guard{filtered_pkt};

    ASSERT_EQ(ldns_pkt_id(filtered_pkt), query_id);
    ASSERT_EQ(ldns_pkt_get_rcode(filtered_pkt), LDNS_RCODE_REFUSED)
            << "$important on CNAME should override whitelist on original domain";
    ASSERT_EQ(last_event.domain, std::string(TRANSPARENT_CNAME_TEST_DOMAIN) + ".");
    ASSERT_FALSE(last_event.whitelist) << "Request should be blocked, not whitelisted";
}

TEST_F(DnsProxyTest, TestReapplySettingsFastUpdate) {
    // Test fast update: only upstreams are updated, filters remain unchanged
    DnsProxySettings settings = make_dnsproxy_settings();
    settings.filter_params = {{{1, "example.com", true}}};
    
    auto [ret, err] = m_proxy->init(settings, {});
    ASSERT_TRUE(ret) << err->str();
    
    // Test that filter works before reapply
    ldns_pkt_ptr response;
    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("example.com", LDNS_RR_TYPE_A, LDNS_RD), response));
    ASSERT_EQ(ldns_pkt_get_rcode(response.get()), LDNS_RCODE_REFUSED);
    
    // Change only upstreams, keep filters unchanged
    settings.upstreams = {{"8.8.8.8"}};
    auto [ret2, err2] = m_proxy->reapply_settings(settings, DnsProxy::RO_SETTINGS);
    ASSERT_TRUE(ret2) << (err2 ? err2->str() : "");
    
    // Test that filter still works after fast reapply (filters preserved)
    response.reset();
    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("example.com", LDNS_RR_TYPE_A, LDNS_RD), response));
    ASSERT_EQ(ldns_pkt_get_rcode(response.get()), LDNS_RCODE_REFUSED);
    
    // Test that new upstream is used (should work with 8.8.8.8)
    response.reset();
    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("google.com", LDNS_RR_TYPE_A, LDNS_RD), response));
    ASSERT_EQ(ldns_pkt_get_rcode(response.get()), LDNS_RCODE_NOERROR);
}

TEST_F(DnsProxyTest, TestReapplySettingsFullUpdate) {
    // Test full update: both upstreams and filters are updated
    DnsProxySettings settings = make_dnsproxy_settings();
    settings.filter_params = {{{1, "example.com", true}}};
    
    auto [ret, err] = m_proxy->init(settings, {});
    ASSERT_TRUE(ret) << err->str();
    
    // Test that original filter works
    ldns_pkt_ptr response;
    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("example.com", LDNS_RR_TYPE_A, LDNS_RD), response));
    ASSERT_EQ(ldns_pkt_get_rcode(response.get()), LDNS_RCODE_REFUSED);

    response.reset();
    ASSERT_NO_FATAL_FAILURE(perform_request(*m_proxy, create_request("test.com", LDNS_RR_TYPE_A, LDNS_RD), response));
    ASSERT_EQ(ldns_pkt_get_rcode(response.get()), LDNS_RCODE_NOERROR);
    
    // Change both upstreams and filters
    settings.upstreams = {{"8.8.8.8"}};
    settings.filter_params = {{{1, "test.com", true}}}; // Different filter
    auto [ret2, err2] = m_proxy->reapply_settings(settings, DnsProxy::RO_SETTINGS | DnsProxy::RO_FILTERS);
    ASSERT_TRUE(ret2) << (err2 ? err2->str() : "");
    
    // Test that old filter no longer works (example.com should pass)
    response.reset();
    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("example.com", LDNS_RR_TYPE_A, LDNS_RD), response));
    ASSERT_EQ(ldns_pkt_get_rcode(response.get()), LDNS_RCODE_NOERROR);
    
    // Test that new filter works (test.com should be blocked)
    response.reset();
    ASSERT_NO_FATAL_FAILURE(perform_request(*m_proxy, create_request("test.com", LDNS_RR_TYPE_A, LDNS_RD), response));
    ASSERT_EQ(ldns_pkt_get_rcode(response.get()), LDNS_RCODE_REFUSED);
}

TEST_F(DnsProxyTest, TestReapplySettingsWithoutInit) {
    // Test that reapply_settings fails if proxy is not initialized
    DnsProxySettings settings = make_dnsproxy_settings();
    
    auto [ret, err] = m_proxy->reapply_settings(settings, DnsProxy::RO_SETTINGS);
    ASSERT_FALSE(ret);
    ASSERT_TRUE(err);
    ASSERT_EQ(err->value(), DnsProxyInitError::AE_PROXY_NOT_SET);
}

TEST_F(DnsProxyTest, TestReapplySettingsFilterError) {
    // Test that reapply_settings handles filter initialization errors
    DnsProxySettings settings = make_dnsproxy_settings();
    
    auto [ret, err] = m_proxy->init(settings, {});
    ASSERT_TRUE(ret) << err->str();
    
    // Try to reapply with invalid filter (non-existent file)
    settings.filter_params = {{{1, "/non/existent/filter/file.txt"}}};
    auto [ret2, err2] = m_proxy->reapply_settings(settings, DnsProxy::RO_SETTINGS | DnsProxy::RO_FILTERS);
    ASSERT_FALSE(ret2);
    ASSERT_TRUE(err2);
}

TEST_F(DnsProxyTest, TestReapplySettingsPreservesEvents) {
    // Test that events continue to work after reapply_settings
    DnsProxySettings settings = make_dnsproxy_settings();
    settings.filter_params = {{{1, "example.com", true}}};

    DnsRequestProcessedEvent last_event{};
    DnsProxyEvents events{.on_request_processed = [&last_event](const DnsRequestProcessedEvent &event) {
        last_event = event;
    }};

    auto [ret, err] = m_proxy->init(settings, events);
    ASSERT_TRUE(ret) << err->str();

    // Reapply settings (fast update)
    settings.upstreams = {{"8.8.8.8"}};
    auto [ret2, err2] = m_proxy->reapply_settings(settings, DnsProxy::RO_SETTINGS);
    ASSERT_TRUE(ret2) << (err2 ? err2->str() : "");

    // Test that events still work
    ldns_pkt_ptr response;
    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("example.com", LDNS_RR_TYPE_A, LDNS_RD), response));

    ASSERT_FALSE(last_event.domain.empty());
    ASSERT_EQ(last_event.domain, "example.com.");
    ASSERT_FALSE(last_event.rules.empty());
}

TEST_F(DnsProxyTest, TestReapplySettingsFiltersOnly) {
    // Test filters-only update: only filters are updated, upstreams remain unchanged
    DnsProxySettings settings = make_dnsproxy_settings();
    settings.filter_params = {{{1, "example.com", true}}};

    auto [ret, err] = m_proxy->init(settings, {});
    ASSERT_TRUE(ret) << err->str();

    // Test that original filter works
    ldns_pkt_ptr response;
    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("example.com", LDNS_RR_TYPE_A, LDNS_RD), response));
    ASSERT_EQ(ldns_pkt_get_rcode(response.get()), LDNS_RCODE_REFUSED);

    response.reset();
    ASSERT_NO_FATAL_FAILURE(perform_request(*m_proxy, create_request("test.com", LDNS_RR_TYPE_A, LDNS_RD), response));
    ASSERT_EQ(ldns_pkt_get_rcode(response.get()), LDNS_RCODE_NOERROR);

    // Change only filters, keep upstreams unchanged
    settings.filter_params = {{{1, "test.com", true}}}; // Different filter
    auto [ret2, err2] = m_proxy->reapply_settings(settings, DnsProxy::RO_FILTERS);
    ASSERT_TRUE(ret2) << (err2 ? err2->str() : "");

    // Test that old filter no longer works (example.com should pass)
    response.reset();
    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("example.com", LDNS_RR_TYPE_A, LDNS_RD), response));
    ASSERT_EQ(ldns_pkt_get_rcode(response.get()), LDNS_RCODE_NOERROR);

    // Test that new filter works (test.com should be blocked)
    response.reset();
    ASSERT_NO_FATAL_FAILURE(perform_request(*m_proxy, create_request("test.com", LDNS_RR_TYPE_A, LDNS_RD), response));
    ASSERT_EQ(ldns_pkt_get_rcode(response.get()), LDNS_RCODE_REFUSED);
}

TEST_F(DnsProxyTest, TestReapplySettingsNoOp) {
    // Test no-op update: both flags are false, nothing should change
    DnsProxySettings settings = make_dnsproxy_settings();
    settings.filter_params = {{{1, "example.com", true}}};
    
    auto [ret, err] = m_proxy->init(settings, {});
    ASSERT_TRUE(ret) << err->str();
    
    // Test that filter works before reapply
    ldns_pkt_ptr response;
    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("example.com", LDNS_RR_TYPE_A, LDNS_RD), response));
    ASSERT_EQ(ldns_pkt_get_rcode(response.get()), LDNS_RCODE_REFUSED);
    
    // Call reapply_settings with both flags false (no-op)
    auto [ret2, err2] = m_proxy->reapply_settings(settings, DnsProxy::RO_NONE);
    ASSERT_TRUE(ret2) << (err2 ? err2->str() : "");
    
    // Test that filter still works after no-op reapply (nothing changed)
    response.reset();
    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("example.com", LDNS_RR_TYPE_A, LDNS_RD), response));
    ASSERT_EQ(ldns_pkt_get_rcode(response.get()), LDNS_RCODE_REFUSED);
}

TEST_F(DnsProxyTest, TestReapplySettingsRoSettingsPreservesListenersAndFilters) {
    // Test that RO_SETTINGS preserves listeners and filter_params, updates everything else
    DnsProxySettings settings = make_dnsproxy_settings_with_listeners();
    settings.filter_params = {{{1, "example.com", true}}};
    settings.blocked_response_ttl_secs = 1000;
    settings.block_ipv6 = false;

    auto [ret, err] = m_proxy->init(settings, {});
    ASSERT_TRUE(ret) << err->str();

    // Reapply with RO_SETTINGS — listeners and filter_params must be preserved
    DnsProxySettings new_settings = make_dnsproxy_settings();
    new_settings.upstreams = {{"1.1.1.1"}};
    new_settings.blocked_response_ttl_secs = 2000;
    new_settings.block_ipv6 = true;
    new_settings.filter_params = {{{2, "other.com", true}}}; // Should be ignored
    auto [ret2, err2] = m_proxy->reapply_settings(new_settings, DnsProxy::RO_SETTINGS);
    ASSERT_TRUE(ret2) << (err2 ? err2->str() : "");

    const auto &current = m_proxy->get_settings();
    ASSERT_NO_FATAL_FAILURE(check_listeners(current, settings.listeners));
    ASSERT_NO_FATAL_FAILURE(check_filter_params(current, settings.filter_params));
    // Other settings should be updated to new_settings values
    DnsProxySettings expected_other = new_settings;
    expected_other.upstreams = {{"1.1.1.1"}};
    ASSERT_NO_FATAL_FAILURE(check_other_settings(current, expected_other));

    // Original filter should still work (example.com blocked)
    ldns_pkt_ptr response;
    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("example.com", LDNS_RR_TYPE_A, LDNS_RD), response));
    ASSERT_EQ(ldns_pkt_get_rcode(response.get()), LDNS_RCODE_REFUSED);
}

TEST_F(DnsProxyTest, TestReapplySettingsRoFiltersPreservesListenersAndOtherSettings) {
    // Test that RO_FILTERS preserves listeners and other settings, updates only filter_params
    DnsProxySettings settings = make_dnsproxy_settings_with_listeners();
    settings.filter_params = {{{1, "example.com", true}}};
    settings.blocked_response_ttl_secs = 1234;
    settings.block_ipv6 = true;
    settings.dns_cache_size = 5000;

    auto [ret, err] = m_proxy->init(settings, {});
    ASSERT_TRUE(ret) << err->str();

    // Reapply with RO_FILTERS only
    DnsProxySettings new_settings = make_dnsproxy_settings();
    new_settings.blocked_response_ttl_secs = 9999; // Should be ignored
    new_settings.block_ipv6 = false; // Should be ignored
    new_settings.dns_cache_size = 1; // Should be ignored
    new_settings.filter_params = {{{1, "test.com", true}}}; // This should be applied
    auto [ret2, err2] = m_proxy->reapply_settings(new_settings, DnsProxy::RO_FILTERS);
    ASSERT_TRUE(ret2) << (err2 ? err2->str() : "");

    const auto &current = m_proxy->get_settings();
    ASSERT_NO_FATAL_FAILURE(check_listeners(current, settings.listeners));
    ASSERT_NO_FATAL_FAILURE(check_filter_params(current, new_settings.filter_params));
    ASSERT_NO_FATAL_FAILURE(check_other_settings(current, settings));

    // Verify new filter is applied (test.com blocked, example.com passes)
    ldns_pkt_ptr response;
    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("test.com", LDNS_RR_TYPE_A, LDNS_RD), response));
    ASSERT_EQ(ldns_pkt_get_rcode(response.get()), LDNS_RCODE_REFUSED);

    response.reset();
    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("example.com", LDNS_RR_TYPE_A, LDNS_RD), response));
    ASSERT_EQ(ldns_pkt_get_rcode(response.get()), LDNS_RCODE_NOERROR);
}

TEST_F(DnsProxyTest, TestReapplySettingsFullUpdatePreservesListeners) {
    // Test that RO_SETTINGS | RO_FILTERS preserves listeners, updates everything else
    DnsProxySettings settings = make_dnsproxy_settings_with_listeners();
    settings.filter_params = {{{1, "example.com", true}}};
    settings.blocked_response_ttl_secs = 1000;

    auto [ret, err] = m_proxy->init(settings, {});
    ASSERT_TRUE(ret) << err->str();

    // Reapply with both flags
    DnsProxySettings new_settings = make_dnsproxy_settings();
    new_settings.upstreams = {{"1.1.1.1"}};
    new_settings.blocked_response_ttl_secs = 2000;
    new_settings.filter_params = {{{1, "test.com", true}}};
    auto [ret2, err2] = m_proxy->reapply_settings(
            new_settings, DnsProxy::RO_SETTINGS | DnsProxy::RO_FILTERS);
    ASSERT_TRUE(ret2) << (err2 ? err2->str() : "");

    const auto &current = m_proxy->get_settings();
    ASSERT_NO_FATAL_FAILURE(check_listeners(current, settings.listeners));
    ASSERT_NO_FATAL_FAILURE(check_filter_params(current, new_settings.filter_params));
    ASSERT_NO_FATAL_FAILURE(check_other_settings(current, new_settings));

    // Old filter should not work, new filter should work
    ldns_pkt_ptr response;
    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("example.com", LDNS_RR_TYPE_A, LDNS_RD), response));
    ASSERT_EQ(ldns_pkt_get_rcode(response.get()), LDNS_RCODE_NOERROR);

    response.reset();
    ASSERT_NO_FATAL_FAILURE(
            perform_request(*m_proxy, create_request("test.com", LDNS_RR_TYPE_A, LDNS_RD), response));
    ASSERT_EQ(ldns_pkt_get_rcode(response.get()), LDNS_RCODE_REFUSED);
}

TEST_F(DnsProxyTest, TestReapplySettingsNoOpPreservesEverything) {
    // Test that RO_NONE preserves everything
    DnsProxySettings settings = make_dnsproxy_settings_with_listeners();
    settings.filter_params = {{{1, "example.com", true}}};
    settings.blocked_response_ttl_secs = 1234;

    auto [ret, err] = m_proxy->init(settings, {});
    ASSERT_TRUE(ret) << err->str();

    // Reapply with RO_NONE — everything must be preserved
    DnsProxySettings new_settings = make_dnsproxy_settings();
    new_settings.upstreams = {{"9.9.9.9"}}; // Should be ignored
    new_settings.blocked_response_ttl_secs = 9999; // Should be ignored
    new_settings.filter_params = {{{2, "other.com", true}}}; // Should be ignored
    auto [ret2, err2] = m_proxy->reapply_settings(new_settings, DnsProxy::RO_NONE);
    ASSERT_TRUE(ret2) << (err2 ? err2->str() : "");

    const auto &current = m_proxy->get_settings();
    ASSERT_NO_FATAL_FAILURE(check_listeners(current, settings.listeners));
    ASSERT_NO_FATAL_FAILURE(check_filter_params(current, settings.filter_params));
    ASSERT_NO_FATAL_FAILURE(check_other_settings(current, settings));
}

TEST_F(DnsProxyTest, RegressCache1) {
    // This test reproduces one possible scenario where the proxy could return an incorrect response due to
    // how caching works. This particular issue has been fixed, the test ensures that it doesn't come back.

    DnsProxySettings settings = make_dnsproxy_settings();
    settings.optimistic_cache = true;
    settings.dns_cache_size = 1;
    settings.block_ech = true;

    DnsRequestProcessedEvent last_event{};
    DnsProxyEvents events{.on_request_processed = [&last_event](const DnsRequestProcessedEvent &event) {
        last_event = event;
    }};

    auto [ret, err] = m_proxy->init(settings, events);
    ASSERT_TRUE(ret) << err->str();

    ldns_pkt_ptr pkt = create_request("tls-ech.dev.", LDNS_RR_TYPE_HTTPS, LDNS_RD);
    ldns_pkt_ptr res;

    DnsMessageInfo info{
            .transparent = false,
    };

    // First request, ECH blocking disabled via override.
    info.settings_overrides.block_ech = false;
    ASSERT_NO_FATAL_FAILURE(perform_request(*m_proxy, pkt, res, &info));
    ASSERT_TRUE(SvcbHttpsHelpers::remove_ech_svcparam(res.get()));

    // Make the cache entry stale.
    SteadyClock::add_time_shift(Secs{3600});

    // Second request, ECH blocking disabled via override.
    // This should trigger optimistic cache behaviour: stale entry is returned and a background fetch is started.
    info.settings_overrides.block_ech = false;
    ASSERT_NO_FATAL_FAILURE(perform_request(*m_proxy, pkt, res, &info));
    ASSERT_TRUE(SvcbHttpsHelpers::remove_ech_svcparam(res.get()));

    // Wait for background fetch.
    std::this_thread::sleep_for(Millis{500});

    // Background fetch "poisons" the cache with an unprocessed response with ECH parameters intact.
    // ECH blocking no longer works.
    info.settings_overrides.block_ech = true;
    ASSERT_NO_FATAL_FAILURE(perform_request(*m_proxy, pkt, res, &info));
    ASSERT_FALSE(SvcbHttpsHelpers::remove_ech_svcparam(res.get()));

    info.settings_overrides.block_ech = false;
    ASSERT_NO_FATAL_FAILURE(perform_request(*m_proxy, pkt, res, &info));
    ASSERT_TRUE(SvcbHttpsHelpers::remove_ech_svcparam(res.get()));
}

TEST_F(DnsProxyTest, RegressCache2) {
    // This test reproduces another possible scenario where the proxy could return an incorrect response due to
    // how caching works. This particular issue has been fixed, the test ensures that it doesn't come back.

    DnsProxySettings settings = make_dnsproxy_settings();
    settings.optimistic_cache = false;
    settings.dns_cache_size = 1;
    settings.block_ech = false;

    DnsRequestProcessedEvent last_event{};
    DnsProxyEvents events{.on_request_processed = [&last_event](const DnsRequestProcessedEvent &event) {
        last_event = event;
    }};

    auto [ret, err] = m_proxy->init(settings, events);
    ASSERT_TRUE(ret) << err->str();

    ldns_pkt_ptr pkt = create_request("tls-ech.dev.", LDNS_RR_TYPE_HTTPS, LDNS_RD);
    ldns_pkt_ptr res;

    DnsMessageInfo info{
            .transparent = false,
    };

    // ECH blocking enabled via override.
    info.settings_overrides.block_ech = true;
    ASSERT_NO_FATAL_FAILURE(perform_request(*m_proxy, pkt, res, &info));
    ASSERT_FALSE(SvcbHttpsHelpers::remove_ech_svcparam(res.get()));

    // Cache could get "poisoned" with a processed response lacking the ECH config.
    info.settings_overrides.block_ech = false;
    ASSERT_NO_FATAL_FAILURE(perform_request(*m_proxy, pkt, res, &info));
    ASSERT_TRUE(SvcbHttpsHelpers::remove_ech_svcparam(res.get()));
}

} // namespace ag::dns::proxy::test
