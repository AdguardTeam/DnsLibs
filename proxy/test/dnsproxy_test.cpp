#include <gtest/gtest.h>
#include <dnsproxy.h>
#include <ldns/ldns.h>
#include <thread>
#include <memory>
#include <ag_net_consts.h>

static constexpr auto DNS64_SERVER_ADDR = "2001:67c:27e4::64";
static constexpr auto IPV4_ONLY_HOST = "ipv4only.arpa.";

TEST(dnsproxy_test, test_dns64) {
    using namespace std::chrono_literals;

    // Assume default settings don't include a DNS64 upstream
    ag::dnsproxy_settings settings = ag::dnsproxy_settings::get_default();
    settings.dns64 = ag::dns64_settings{
            .upstream = {
                    .dns_server = DNS64_SERVER_ADDR,
                    .options = ag::upstream::options{
                            .timeout = 5000ms
                    }
            },
            .max_tries = 5,
            .wait_time = 1s,
    };

    ag::dnsproxy proxy;
    ASSERT_TRUE(proxy.init(settings, ag::dnsproxy_events{}));

    ag::ldns_pkt_ptr pkt(
            ldns_pkt_query_new(
                    ldns_dname_new_frm_str(IPV4_ONLY_HOST),
                    LDNS_RR_TYPE_AAAA, // Request AAAA for an IPv4 only host, forcing synthesis
                    LDNS_RR_CLASS_IN,
                    LDNS_RD));

    const auto buffer = std::unique_ptr<ldns_buffer, ag::ftor<ldns_buffer_free>>(
            ldns_buffer_new(ag::REQUEST_BUFFER_INITIAL_CAPACITY));

    ldns_status status = ldns_pkt2buffer_wire(buffer.get(), pkt.get());
    ASSERT_EQ(status, LDNS_STATUS_OK) << ldns_get_errorstr_by_id(status);

    std::this_thread::sleep_for(5s); // Let DNS64 discovery happen

    const auto resp_data = proxy.handle_message({ldns_buffer_at(buffer.get(), 0),
                                                 ldns_buffer_position(buffer.get())});

    ldns_pkt *resp;
    status = ldns_wire2pkt(&resp, resp_data.data(), resp_data.size());
    ASSERT_EQ(status, LDNS_STATUS_OK) << ldns_get_errorstr_by_id(status);
    const ag::ldns_pkt_ptr response(resp);

    ASSERT_GT(ldns_pkt_ancount(response.get()), 0);

    proxy.deinit();
}
