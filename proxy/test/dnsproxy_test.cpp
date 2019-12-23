#include <gtest/gtest.h>
#include <dnsproxy.h>
#include <ldns/ldns.h>
#include <thread>
#include <memory>
#include <ag_utils.h>
#include <ag_net_consts.h>

static constexpr auto DNS64_SERVER_ADDR = "2001:67c:27e4::64";
static constexpr auto IPV4_ONLY_HOST = "ipv4only.arpa.";
static constexpr auto CNAME_BLOCKING_HOST = "test2.meshkov.info";

class dnsproxy_test : public ::testing::Test {
protected:
    ag::dnsproxy proxy;

    ~dnsproxy_test() override {
        proxy.deinit();
    }

    void SetUp() override {
        ag::set_default_log_level(ag::TRACE);
    }
};

static void perform_request(ag::dnsproxy &proxy, ag::ldns_pkt_ptr &request, ag::ldns_pkt_ptr &response) {
    const std::unique_ptr<ldns_buffer, ag::ftor<ldns_buffer_free>> buffer(
            ldns_buffer_new(ag::REQUEST_BUFFER_INITIAL_CAPACITY));

    ldns_status status = ldns_pkt2buffer_wire(buffer.get(), request.get());
    ASSERT_EQ(status, LDNS_STATUS_OK) << ldns_get_errorstr_by_id(status);

    const auto resp_data = proxy.handle_message({ldns_buffer_at(buffer.get(), 0),
                                                 ldns_buffer_position(buffer.get())});

    ldns_pkt *resp;
    status = ldns_wire2pkt(&resp, resp_data.data(), resp_data.size());
    ASSERT_EQ(status, LDNS_STATUS_OK) << ldns_get_errorstr_by_id(status);
    response = ag::ldns_pkt_ptr(resp);
}

TEST_F(dnsproxy_test, test_dns64) {
    using namespace std::chrono_literals;

    // Assume default settings don't include a DNS64 upstream
    ag::dnsproxy_settings settings = ag::dnsproxy_settings::get_default();
    settings.dns64 = ag::dns64_settings{
            .upstream_settings = {
                    .address = DNS64_SERVER_ADDR,
                    .timeout = 5000ms,
            },
            .max_tries = 5,
            .wait_time = 1s,
    };

    ASSERT_TRUE(proxy.init(settings, ag::dnsproxy_events{}));
    std::this_thread::sleep_for(5s); // Let DNS64 discovery happen

    ag::ldns_pkt_ptr pkt(
            ldns_pkt_query_new(
                    ldns_dname_new_frm_str(IPV4_ONLY_HOST),
                    LDNS_RR_TYPE_AAAA, // Request AAAA for an IPv4 only host, forcing synthesis
                    LDNS_RR_CLASS_IN,
                    LDNS_RD));

    ag::ldns_pkt_ptr response;
    ASSERT_NO_FATAL_FAILURE(perform_request(proxy, pkt, response));

    ASSERT_GT(ldns_pkt_ancount(response.get()), 0);
}

TEST_F(dnsproxy_test, test_ipv6_blocking) {
    ag::dnsproxy_settings settings = ag::dnsproxy_settings::get_default();
    settings.block_ipv6 = true;
    settings.ipv6_available = false;

    ASSERT_TRUE(proxy.init(settings, {}));

    ag::ldns_pkt_ptr pkt(
            ldns_pkt_query_new(
                    ldns_dname_new_frm_str(IPV4_ONLY_HOST),
                    LDNS_RR_TYPE_AAAA,
                    LDNS_RR_CLASS_IN,
                    LDNS_RD));

    ag::ldns_pkt_ptr response;
    ASSERT_NO_FATAL_FAILURE(perform_request(proxy, pkt, response));

    ASSERT_EQ(ldns_pkt_ancount(response.get()), 0);
    ASSERT_EQ(ldns_pkt_get_rcode(response.get()), LDNS_RCODE_NOERROR);
    ASSERT_EQ(ldns_pkt_nscount(response.get()), 1);
}

TEST_F(dnsproxy_test, test_cname_blocking) {
    ag::dnsproxy_settings settings = ag::dnsproxy_settings::get_default();
    settings.filter_params = {{{1, "cname_blocking_test_filter.txt"}}};

    ASSERT_TRUE(proxy.init(settings, {}));

    ag::ldns_pkt_ptr pkt(
            ldns_pkt_query_new(
                    ldns_dname_new_frm_str(CNAME_BLOCKING_HOST),
                    LDNS_RR_TYPE_A,
                    LDNS_RR_CLASS_IN,
                    LDNS_RD));

    ag::ldns_pkt_ptr response;
    ASSERT_NO_FATAL_FAILURE(perform_request(proxy, pkt, response));

    ASSERT_EQ(ldns_pkt_ancount(response.get()), 0);
    ASSERT_EQ(ldns_pkt_get_rcode(response.get()), LDNS_RCODE_NXDOMAIN);
}
