#include <gtest/gtest.h>
#include <upstream.h>
#include <functional>
#include <future>
#include <thread>
#include <ldns/dname.h>
#include <ldns/keys.h>
#include <ldns/rbtree.h>
#include <ldns/host2str.h> // Requires include keys.h and rbtree.h above
#include <ldns/packet.h>
#include <ldns/wire2host.h>
#include <ag_logger.h>
#include <ag_utils.h>
#include <dns_crypt_ldns.h>

static constexpr std::chrono::seconds default_timeout(10);

static const ag::logger &logger() {
    static auto result = ag::create_logger("test_upstream_logger");
    return result;
}

class upstream_test : public ::testing::Test {
protected:
    void SetUp() override {
        ag::set_default_log_level(ag::TRACE);
    }
};

template<typename... Ts>
struct upstream_param_test : upstream_test, ::testing::WithParamInterface<Ts...> {};

static ag::ldns_pkt_ptr create_test_message() {
    ldns_pkt *pkt = ldns_pkt_query_new(ldns_dname_new_frm_str("google-public-dns-a.google.com."), LDNS_RR_TYPE_A,
                                       LDNS_RR_CLASS_IN, LDNS_RD);
    static size_t id = 0;
    ldns_pkt_set_id(pkt, id++);
    return ag::ldns_pkt_ptr(pkt);
}

static void assert_response(const ldns_pkt &reply) {
    size_t ancount = ldns_pkt_ancount(&reply);
    ASSERT_EQ(1, ancount) << "DNS upstream returned reply with wrong number of answers - " << ancount;
    ldns_rr *first_rr = ldns_rr_list_rr(ldns_pkt_answer(&reply), 0);
    ASSERT_EQ(LDNS_RR_TYPE_A, ldns_rr_get_type(first_rr)) << "DNS upstream returned wrong answer type instead of A: "
                                                          << ldns_rr_type2str(ldns_rr_get_type(first_rr));
    ldns_rdf *rdf = ldns_rr_rdf(first_rr, 0);
    ag::uint8_view ip{ldns_rdf_data(rdf), ldns_rdf_size(rdf)};
    static const auto ip8888 = ag::utils::to_string_view<uint8_t>({8, 8, 8, 8});
    ASSERT_EQ(ip, ip8888) << "DNS upstream returned wrong answer instead of 8.8.8.8: ";// << std::string(ip).c_str(); // TODO
}

static void check_upstream(ag::upstream &upstream, const std::string &addr) {
    auto req = create_test_message();
    auto[reply, err] = upstream.exchange(req.get());
    ASSERT_FALSE(err) << "Couldn't talk to upstream " + addr + ": " + *err;
    assert_response(*reply);
}

#if 1 // TODO old
struct upstream_test_data_old {
    std::string address;
    std::initializer_list<std::string> bootstrap;
};

class upstream_test_with_data_old : public upstream_test, public ::testing::WithParamInterface<upstream_test_data_old> {};

static const std::initializer_list<std::string> default_bootstrap_list_old{"8.8.8.8", "1.1.1.1"};

static const upstream_test_data_old upstream_test_addresses_old[]{
    {
        "tls://1.1.1.1",
//        {}
        default_bootstrap_list_old
    },
    {
        "8.8.8.8",
        default_bootstrap_list_old
    },
    {
        "1.1.1.1",
        default_bootstrap_list_old
    },
    { // TODO FAIL
        "tcp://8.8.8.8",
        default_bootstrap_list_old
    },
    {
        "tcp://1.1.1.1",
        default_bootstrap_list_old
    },
    {
        "tls://one.one.one.one",
        default_bootstrap_list_old
    },
    { // TODO FAIL
        // AdGuard DNS (DNSCrypt)
        "sdns://AQIAAAAAAAAAFDE3Ni4xMDMuMTMwLjEzMDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20",
        {}
    },
    { // TODO FAIL
        // AdGuard Family (DNSCrypt)
        "sdns://AQIAAAAAAAAAFDE3Ni4xMDMuMTMwLjEzMjo1NDQzILgxXdexS27jIKRw3C7Wsao5jMnlhvhdRUXWuMm1AFq6ITIuZG5zY3J5cHQuZmFtaWx5Lm5zMS5hZGd1YXJkLmNvbQ",
        {}
    },
    {
        // Cisco OpenDNS (DNSCrypt)
        "sdns://AQAAAAAAAAAADjIwOC42Ny4yMjAuMjIwILc1EUAgbyJdPivYItf9aR6hwzzI1maNDL4Ev6vKQ_t5GzIuZG5zY3J5cHQtY2VydC5vcGVuZG5zLmNvbQ",
        {}
    },
    {
        "https://dns.cloudflare.com/dns-query",
        default_bootstrap_list_old
    },
};

TEST_P(upstream_test_with_data_old, test_dns_query_old) { // TODO
    const auto &address = GetParam().address;
    const auto &bootstrap_list = GetParam().bootstrap;
    ag::ldns_pkt_ptr pkt = create_test_message();
    ag::upstream::options opts = {
        .bootstrap = bootstrap_list,
        .timeout = std::chrono::milliseconds(5000)
    };
    auto[upstream, err1] = ag::upstream::address_to_upstream(address, opts);
    ASSERT_FALSE(err1) << *err1;
    auto[reply, err2] = upstream->exchange(&*pkt);
    ASSERT_FALSE(err2) << *err2;
    ASSERT_NE(reply, nullptr);
    assert_response(*reply);
    ldns_pkt_print(stderr, &*reply);
    ASSERT_FALSE(std::get<ag::err_string>(upstream->exchange(&*pkt)));
    sleep(2);
    ASSERT_FALSE(std::get<ag::err_string>(upstream->exchange(&*pkt)));
    sleep(3);
    ASSERT_FALSE(std::get<ag::err_string>(upstream->exchange(&*pkt)));
}

INSTANTIATE_TEST_CASE_P(test_dns_query, upstream_test_with_data_old, testing::ValuesIn(upstream_test_addresses_old));

TEST_F(upstream_test, DISABLED_doh_concurrent_requests) {
    static constexpr size_t REQUESTS_NUM = 128;
    static constexpr size_t WORKERS_NUM = 16;

    ag::upstream::options opts = {
        .bootstrap = default_bootstrap_list_old,
        .timeout = std::chrono::milliseconds(5000),
        // .server_ip = ag::uint8_array<4>{ 104, 19, 199, 29 }, // TODO
        // .server_ip = ag::uint8_array<16>{ 0x26, 0x06, 0x47, 0x00, 0x30, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x68, 0x13, 0xc7, 0x1d }, // TODO
    };
    auto[upstream, err1] = ag::upstream::address_to_upstream("https://dns.cloudflare.com/dns-query", opts);
    ASSERT_FALSE(err1) << *err1;

    std::thread workers[WORKERS_NUM];

    for (size_t i = 0; i < WORKERS_NUM; ++i) {
        workers[i] = std::thread(
            [us = upstream.get(), i] () {
                for (size_t j = 0; j < REQUESTS_NUM; ++j) {
                    ag::ldns_pkt_ptr pkt = create_test_message();
                    auto[reply, err2] = us->exchange(pkt.get());
                    ASSERT_FALSE(err2) << "i=" << i << ": " << *err2;
                    ASSERT_NE(reply, nullptr);
                    assert_response(*reply);
                }
            });
    }

    for (size_t i = 0; i < WORKERS_NUM; ++i) {
        workers[i].join();
        SPDLOG_INFO("worker #{} done", i);
    }
}

#endif // TODO old

struct timeout_test_data {
    using f_result_type = ag::err_string; // TODO name
    using f_type = f_result_type(*)(size_t, ag::upstream &, std::chrono::milliseconds); // TODO name
    using ff_type = f_result_type(size_t, ag::upstream &, std::chrono::milliseconds); // TODO name

    std::chrono::milliseconds timeout;
    size_t count = 10;
    std::string_view address;
    std::initializer_list<std::string> bootstrap;
    f_type f; // TODO name
};
static const timeout_test_data timeout_data[]{
    // test_bootstrap_timeout
    {
        std::chrono::milliseconds(100),
        10,
        "tls://one.one.one.one",
        {"8.8.8.8:555"},
        [](size_t idx, ag::upstream &upstream, std::chrono::milliseconds timeout) -> timeout_test_data::f_result_type {
            infolog(logger(), "Start {}", idx);
            ag::utils::timer timer;
            if (rand() % 2 == 1) std::this_thread::sleep_for(10000 * timeout); // TODO
            auto req = create_test_message();
            auto[reply, reply_err] = upstream.exchange(req.get());
            if (!reply_err) {
                return "The upstream must have timed out";
            }
            auto elapsed = timer.elapsed<decltype(timeout)>();
//            if (true || elapsed > 2 * timeout) { // TODO
            if (elapsed > 2 * timeout) {
                return "Exchange took more time than the configured timeout: " + std::to_string(elapsed.count()) + "ms"; // TODO use std::chrono::operator<< since C++20
            }
            infolog(logger(), "Finished " + std::to_string(idx));
            return std::nullopt;
        }
    },
// test_upstream_race
    {
        std::chrono::milliseconds(5000),
        5,
        "tls://1.1.1.1",
        {},
        [](size_t idx, ag::upstream &upstream, std::chrono::milliseconds timeout) -> timeout_test_data::f_result_type {
            infolog(logger(), "Start {}", idx);
            auto req = create_test_message();
            auto[reply, reply_err] = upstream.exchange(req.get());
            if (reply_err) {
                return "Failed to resolve: " + *reply_err;
            }
            assert_response(*reply);
            infolog(logger(), "Finished " + std::to_string(idx));
            return std::nullopt;
        }
    },
};

struct upstream_timeout_test : upstream_param_test<timeout_test_data> {};

TEST_P(upstream_timeout_test, test_timeout) {
    const auto &p = GetParam();
    // Specifying some wrong port instead so that bootstrap DNS timed out for sure
    auto[upstream_ptr, upstream_err] = ag::upstream::address_to_upstream(p.address, {p.bootstrap, p.timeout});
    ASSERT_FALSE(upstream_err) << "Cannot create upstream: " << *upstream_err;
    std::vector<std::future<timeout_test_data::f_result_type>> futures;
    futures.reserve(p.count);
    for (size_t i = 0, e = p.count; i < e; ++i) {
//        futures.emplace_back(ag::utils::async_detached(p.f, i, std::ref(*upstream_ptr), p.timeout)); // TODO
        futures.emplace_back(ag::utils::async_detached([f = p.f, i, upstream_ptr = upstream_ptr, timeout = p.timeout] {
            return f(i, *upstream_ptr, timeout);
        }));

    }
    bool failed = false;
    for (size_t i = 0, e = futures.size(); i < e; ++i) {
        auto &future = futures[i];
        auto future_status = future.wait_for(10 * p.timeout);
        if (future_status == std::future_status::timeout) {
            errlog(logger(), "No response in time for {}", i);
            failed = true;
            continue;
        }
        auto result = future.get();
        if (result) {
            errlog(logger(), "Aborted: {}", *result);
        } else {
            infolog(logger(), "Got result from {}", i);
        }
    }
    if (failed) {
//        ASSERT_FALSE(failed); // TODO
    }
}

INSTANTIATE_TEST_CASE_P(test_timeout, upstream_timeout_test, testing::ValuesIn(timeout_data));

TEST_F(upstream_test, test_tls_pool_reconnect) {
    // TODO code duplication
    auto[upstream_ptr, upstream_err] = ag::upstream::address_to_upstream("tls://one.one.one.one", {{"8.8.8.8:53"}, default_timeout});
    ASSERT_FALSE(upstream_err) << "Cannot create upstream: " << *upstream_err;
    // Send the first test message
    auto first_req = create_test_message();
    auto[reply, reply_err] = upstream_ptr->exchange(first_req.get());
    ASSERT_FALSE(reply_err) << "First DNS message failed: " + *reply_err;
    assert_response(*reply);
#if 0 // TODO ???
    // Now let's close the pooled connection and return it back to the pool
    p := u.(*dnsOverTLS)
    conn, _ := p.pool.Get()
    conn.Close()
    p.pool.Put(conn)

    // Send the second test message
    req = createTestMessage()
    reply, err = u.Exchange(req)
    if err != nil {
        t.Fatalf("second DNS message failed: %s", err)
    }
    assertResponse(t, reply)

    // Now assert that the number of connections in the pool is not changed
    if len(p.pool.conns) != 1 {
        t.Fatal("wrong number of pooled connections")
    }
#endif
}

TEST_F(upstream_test, test_tls_pool_dead_line) {
    // TODO code duplication
    // Create TLS upstream
    auto[upstream_ptr, upstream_err] = ag::upstream::address_to_upstream("tls://one.one.one.one", {{"8.8.8.8:53"}, default_timeout});
    ASSERT_FALSE(upstream_err) << "Cannot create upstream: " << *upstream_err;

    // Send the first test message
    auto first_req = create_test_message();
    auto[reply, reply_err] = upstream_ptr->exchange(first_req.get());
    ASSERT_FALSE(reply_err) << "First DNS message failed: " + *reply_err;
    assert_response(*reply);
#if 0 // TODO ???
    p := u.(*dnsOverTLS)

    // Now let's get connection from the pool and use it
    conn, err := p.pool.Get()
    if err != nil {
        t.Fatalf("couldn't get connection from pool: %s", err)
    }
    response, err = p.exchangeConn(conn, req)
    if err != nil {
        t.Fatalf("first DNS message failed: %s", err)
    }
    assertResponse(t, response)

    // Update connection's deadLine and put it back to the pool
    err = conn.SetDeadline(time.Now().Add(10 * time.Hour))
    if err != nil {
        t.Fatalf("can't set new deadLine for connection. Looks like it's already closed: %s", err)
    }
    p.pool.Put(conn)

    // Get connection from the pool and reuse it
    conn, err = p.pool.Get()
    if err != nil {
        t.Fatalf("couldn't get connection from pool: %s", err)
    }
    response, err = p.exchangeConn(conn, req)
    if err != nil {
        t.Fatalf("first DNS message failed: %s", err)
    }
    assertResponse(t, response)

    // Set connection's deadLine to the past and try to reuse it
    err = conn.SetDeadline(time.Now().Add(-10 * time.Hour))
    if err != nil {
        t.Fatalf("can't set new deadLine for connection. Looks like it's already closed: %s", err)
    }

    // Connection with expired deadLine can't be used
    response, err = p.exchangeConn(conn, req)
    if err == nil {
        t.Fatalf("this connection should be already closed, got response %s", response)
    }
#endif
}

struct dns_truncated_test : upstream_param_test<std::string_view> {};

// TODO
static constexpr std::string_view truncated_test_data[]{
    // AdGuard DNS
//    "176.103.130.130:53",
    // Google DNS
//    "8.8.8.8:53",
    // See the details here: https://github.com/AdguardTeam/AdGuardHome/issues/524
    // AdGuard DNS (DNSCrypt)
    "sdns://AQIAAAAAAAAAFDE3Ni4xMDMuMTMwLjEzMDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20",
    // Cisco OpenDNS (DNSCrypt)
//    "sdns://AQAAAAAAAAAADjIwOC42Ny4yMjAuMjIwILc1EUAgbyJdPivYItf9aR6hwzzI1maNDL4Ev6vKQ_t5GzIuZG5zY3J5cHQtY2VydC5vcGVuZG5zLmNvbQ",
};

TEST_P(dns_truncated_test, test_dns_truncated) {
    const auto &address = GetParam();
    auto[upstream, upstream_err] = ag::upstream::address_to_upstream(address, {.timeout=std::chrono::seconds(5)});
    ASSERT_FALSE(upstream_err) << "Error while creating an upstream: " << *upstream_err;
    auto request = ag::dnscrypt::create_request_ldns_pkt(LDNS_RR_TYPE_TXT, LDNS_RR_CLASS_IN, LDNS_RD,
                                                         "unit-test2.dns.adguard.com.", std::nullopt);
    ldns_pkt_set_random_id(request.get());
    auto[res, err] = upstream->exchange(request.get());
    ASSERT_FALSE(err) << "Error while making a request: " << *err;
    ASSERT_FALSE(ldns_pkt_tc(res.get())) << "Response must NOT be truncated";
}

INSTANTIATE_TEST_CASE_P(dns_truncated_test, dns_truncated_test, testing::ValuesIn(truncated_test_data));

struct dial_context_test_data {
    std::initializer_list<std::string> addresses;
    std::string_view host;
};

struct dial_context_test : upstream_param_test<dial_context_test_data> {};

static const dial_context_test_data test_dial_context_data[]{
    {
        {"216.239.32.59:443"},
        "dns.google.com"
    },
    {
        {"176.103.130.130:855", "176.103.130.130:853"},
        "dns.adguard.com"
    },
    {
        {"1.1.1.1:5555", "1.1.1.1:853", "8.8.8.8:85"},
        "dns.cloudflare.com"
    },
};

// See the details here: https://github.com/AdguardTeam/dnsproxy/issues/18
TEST_P(dial_context_test, test_dial_context) {
    // TODO
#if 0
    dialContext := createDialContext(test.addresses, 2*time.Second)
    _, err := dialContext(context.TODO(), "tcp", "")
    if err != nil {
        t.Fatalf("Couldn't dial to %s: %s", test.host, err)
    }
#endif
}

INSTANTIATE_TEST_CASE_P(dial_context_test, dial_context_test, testing::ValuesIn(test_dial_context_data));

struct upstream_test_data {
    std::string address;
    std::initializer_list<std::string> bootstrap;
};

static const upstream_test_data test_upstreams_data[]{
    {
        "8.8.8.8:53",
        {"8.8.8.8:53"}
    },
    {
        "1.1.1.1",
        {}
    },
    {
        "1.1.1.1",
        {"1.0.0.1"}
    },
    {
        "tcp://1.1.1.1:53",
        {}
    },
    {
        "176.103.130.130:5353",
        {}
    },
    {
        "tls://1.1.1.1",
#if 1
        {}
#else
        {"1.1.1.1"}
#endif
    },
    {
        "tls://9.9.9.9:853",
#if 1
        {} // TODO original
#else
        {"9.9.9.9"}
#endif
    },
    {
        "tls://dns.adguard.com",
        {"8.8.8.8:53"}
    },
    {
        "tls://dns.adguard.com:853",
        {"8.8.8.8:53"}
    },
    {
        "tls://dns.adguard.com:853",
        {"8.8.8.8"}
    },
    {
        "tls://one.one.one.one",
        {}
    },
    {
        "https://dns9.quad9.net:443/dns-query",
        {"8.8.8.8"}
    },
    {
        "https://dns.cloudflare.com/dns-query",
        {"8.8.8.8:53"}
    },
    {
        "https://dns.google/dns-query",
#if 0
        {}
#else
        {"8.8.8.8", "1.1.1.1"}
#endif
    },
    {
        // AdGuard DNS (DNSCrypt)
        "sdns://AQIAAAAAAAAAFDE3Ni4xMDMuMTMwLjEzMDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20",
        {}
    },
    {
        // AdGuard Family (DNSCrypt)
        "sdns://AQIAAAAAAAAAFDE3Ni4xMDMuMTMwLjEzMjo1NDQzILgxXdexS27jIKRw3C7Wsao5jMnlhvhdRUXWuMm1AFq6ITIuZG5zY3J5cHQuZmFtaWx5Lm5zMS5hZGd1YXJkLmNvbQ",
        {"8.8.8.8"}
    },
    {
        // Cisco OpenDNS (DNSCrypt)
        "sdns://AQAAAAAAAAAADjIwOC42Ny4yMjAuMjIwILc1EUAgbyJdPivYItf9aR6hwzzI1maNDL4Ev6vKQ_t5GzIuZG5zY3J5cHQtY2VydC5vcGVuZG5zLmNvbQ",
        {"8.8.8.8:53"}
    },
    {
        // Cloudflare DNS (DoH)
        "sdns://AgcAAAAAAAAABzEuMC4wLjGgENk8mGSlIfMGXMOlIlCcKvq7AVgcrZxtjon911-ep0cg63Ul-I8NlFj4GplQGb_TTLiczclX57DvMV8Q-JdjgRgSZG5zLmNsb3VkZmxhcmUuY29tCi9kbnMtcXVlcnk",
        {"8.8.8.8:53"}
    },
    {
        // Google (Plain)
        "sdns://AAcAAAAAAAAABzguOC44Ljg",
        {}
    },
    {
        // AdGuard DNS (DNS-over-TLS)
        "sdns://AwAAAAAAAAAAAAAPZG5zLmFkZ3VhcmQuY29t",
        {"8.8.8.8:53"}
    },
    {
        "https://1.1.1.1/dns-query",
        {}
    },
};

TEST_F(upstream_test, test_upstreams) {
    // TODO duplication
    using namespace std::chrono_literals;
    for (const auto &[address, bootstrap_list] : test_upstreams_data) {
        auto[upstream_ptr, upstream_err] = ag::upstream::address_to_upstream(address, {bootstrap_list, 5s}); // TODO 5s
        ASSERT_FALSE(upstream_err) << "Failed to generate upstream from address " << address <<  ": " << *upstream_err;
        check_upstream(*upstream_ptr, address);
    }
}

struct upstream_default_options_test : upstream_param_test<std::string> {};

static const std::string test_upstream_default_options_data[]{
    "tls://1.1.1.1",
    "8.8.8.8",
};

TEST_P(upstream_default_options_test, test_upstream_default_options) {
    // TODO duplication
    const auto &address = GetParam();
    auto[upstream_ptr, upstream_err] = ag::upstream::address_to_upstream(address, {{}, default_timeout});
    ASSERT_FALSE(upstream_err) << "Failed to generate upstream from address " << address << ": " << *upstream_err;
    check_upstream(*upstream_ptr, address);
}

INSTANTIATE_TEST_CASE_P(upstream_default_options_test, upstream_default_options_test, testing::ValuesIn(test_upstream_default_options_data));

struct upstreams_invalid_bootstrap_test : upstream_param_test<upstream_test_data> {};

static const upstream_test_data test_upstreams_invalid_bootstrap_data[]{
    {
        "tls://dns.adguard.com",
        {"1.1.1.1:555", "8.8.8.8:53"},
    },
    {
        "tls://dns.adguard.com:853",
        {"1.0.0.1", "8.8.8.8:535"},
    },
    {
        "https://dns.cloudflare.com/dns-query",
        {"8.8.8.1", "1.0.0.1"},
    },
    {
        "https://dns9.quad9.net:443/dns-query",
        {"1.2.3.4:79", "8.8.8.8:53"},
    },
    {
        // Cloudflare DNS (DoH)
        "sdns://AgcAAAAAAAAABzEuMC4wLjGgENk8mGSlIfMGXMOlIlCcKvq7AVgcrZxtjon911-ep0cg63Ul-I8NlFj4GplQGb_TTLiczclX57DvMV8Q-JdjgRgSZG5zLmNsb3VkZmxhcmUuY29tCi9kbnMtcXVlcnk",
        {"8.8.8.8:53", "8.8.8.1:53"},
    },
    {
        // AdGuard DNS (DNS-over-TLS)
        "sdns://AwAAAAAAAAAAAAAPZG5zLmFkZ3VhcmQuY29t",
        {"1.2.3.4:55", "8.8.8.8"},
    },
};

// Test for DoH and DoT upstreams with two bootstraps (only one is valid)
TEST_P(upstreams_invalid_bootstrap_test, test_upstreams_invalid_bootstrap) {
    // TODO duplication
    const auto &[address, bootstrap] = GetParam();
    auto[upstream_ptr, upstream_err] = ag::upstream::address_to_upstream(address, {bootstrap, default_timeout});
    ASSERT_FALSE(upstream_err) << "Failed to generate upstream from address " << address << ": " << *upstream_err;
    check_upstream(*upstream_ptr, address);
}

INSTANTIATE_TEST_CASE_P(upstreams_invalid_bootstrap_test, upstreams_invalid_bootstrap_test, testing::ValuesIn(test_upstreams_invalid_bootstrap_data));

struct upstreams_with_server_ip_test_data {
    std::string address;
    std::initializer_list<std::string> bootstrap;
    ag::ip_address_variant server_ip;
};

struct upstreams_with_server_ip_test : upstream_param_test<upstreams_with_server_ip_test_data> {};

// use invalid bootstrap to make sure it fails if tries to use it
static const std::initializer_list<std::string> invalid_bootstrap{"1.2.3.4:55"}; // TODO name

static const upstreams_with_server_ip_test_data test_upstreams_with_server_ip_data[]{
    {
        "tls://dns.adguard.com",
        invalid_bootstrap,
        ag::ipv4_address_array{176, 103, 130, 130}
    },
    {
        "https://dns.adguard.com/dns-query",
        invalid_bootstrap,
        ag::ipv4_address_array{176, 103, 130, 130}
    },
    {
        // AdGuard DNS DOH with the IP address specified
        "sdns://AgcAAAAAAAAADzE3Ni4xMDMuMTMwLjEzMAAPZG5zLmFkZ3VhcmQuY29tCi9kbnMtcXVlcnk",
        invalid_bootstrap,
        {}
    },
    {
        // AdGuard DNS DOT with the IP address specified
        "sdns://AwAAAAAAAAAAEzE3Ni4xMDMuMTMwLjEzMDo4NTMAD2Rucy5hZGd1YXJkLmNvbQ",
        invalid_bootstrap,
        {}
    },
};

TEST_P(upstreams_with_server_ip_test, test_upstreams_with_server_ip) {
    // TODO duplication
    const auto &[address, bootstrap, server_ip] = GetParam();
    auto[upstream_ptr, upstream_err] = ag::upstream::address_to_upstream(address, {bootstrap, default_timeout, server_ip});
    ASSERT_FALSE(upstream_err) << "Failed to generate upstream from address " << address << ": " << *upstream_err;
    check_upstream(*upstream_ptr, address);
}

INSTANTIATE_TEST_CASE_P(upstreams_with_server_ip_test, upstreams_with_server_ip_test, testing::ValuesIn(test_upstreams_with_server_ip_data));
