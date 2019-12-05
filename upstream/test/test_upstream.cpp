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
#include <spdlog/fmt/bundled/chrono.h>
#include <ag_logger.h>
#include <ag_utils.h>
#include <dns_crypt_ldns.h>

static constexpr std::chrono::seconds DEFAULT_TIMEOUT(10);

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

namespace concat_err_string {

ag::err_string &operator+=(ag::err_string &result, const ag::err_string &err) {
    if (err) {
        if (!result) {
            result = std::string{};
        }
        if (result) {
            *result += AG_FMT("{}\n", *err);
        }
    }
    return result;
}

} // namespace concat_err_string

static ag::ldns_pkt_ptr create_test_message() {
    ldns_pkt *pkt = ldns_pkt_query_new(ldns_dname_new_frm_str("google-public-dns-a.google.com."), LDNS_RR_TYPE_A,
                                       LDNS_RR_CLASS_IN, LDNS_RD);
    static size_t id = 0;
    ldns_pkt_set_id(pkt, id++);
    return ag::ldns_pkt_ptr(pkt);
}

[[nodiscard]] static ag::err_string assert_response(const ldns_pkt &reply) {
    size_t ancount = ldns_pkt_ancount(&reply);
    if (ancount != 1) {
        return AG_FMT("DNS upstream returned reply with wrong number of answers: {}", ancount);
    }
    ldns_rr *first_rr = ldns_rr_list_rr(ldns_pkt_answer(&reply), 0);
    if (ldns_rr_get_type(first_rr) != LDNS_RR_TYPE_A) {
        return AG_FMT("DNS upstream returned wrong answer type instead of A: {}",
                      ldns_rr_type2str(ldns_rr_get_type(first_rr)));
    }
    ldns_rdf *rdf = ldns_rr_rdf(first_rr, 0);
    ag::uint8_view ip{ldns_rdf_data(rdf), ldns_rdf_size(rdf)};
    static const auto ip8888 = ag::utils::to_string_view<uint8_t>({8, 8, 8, 8});
    if (ip != ip8888) {
        return "DNS upstream returned wrong answer instead of 8.8.8.8";
    }
    return std::nullopt;
}

[[nodiscard]] static ag::err_string check_upstream(ag::upstream &upstream, const std::string &addr) {
    auto req = create_test_message();
    auto[reply, err] = upstream.exchange(req.get());
    if (err) {
        return AG_FMT("Couldn't talk to upstream {}: {}", addr, *err);
    }
    return assert_response(*reply);
}

using err_futures = std::vector<std::future<ag::err_string>>;

template<typename F>
static err_futures make_indexed_futures(size_t count, const F &f) {
    err_futures futures;
    futures.reserve(count);
    for (size_t i = 0, e = count; i < e; ++i) {
        futures.emplace_back(ag::utils::async_detached(f, i));
    }
    return futures;
}

static void check_all_futures(err_futures &futures) {
    using namespace concat_err_string;
    ag::err_string err;
    for (auto &future : futures) {
        err += future.get();
    }
    ASSERT_FALSE(err) << *err;
}

template<typename F>
static void parallel_test_basic_n(size_t count, const F &f) {
    auto futures = make_indexed_futures(count, f);
    check_all_futures(futures);
}

template<typename T, typename F>
static void parallel_test_basic(const T &data, const F &function) {
    err_futures futures;
    futures.reserve(std::size(data));
    for (const auto &[address, bootstrap, server_ip] : data) {
        futures.emplace_back(ag::utils::async_detached(function, address, bootstrap, server_ip));
    }
    check_all_futures(futures);
}

template<typename T>
static void parallel_test(const T &data) {
    parallel_test_basic(data, [](const auto &address, const auto &bootstrap, const auto &server_ip) -> ag::err_string {
        auto[upstream_ptr, upstream_err] = ag::upstream::address_to_upstream(address, {bootstrap, DEFAULT_TIMEOUT});
        if (upstream_err) {
            return AG_FMT("Failed to generate upstream from address {}: {}", address, *upstream_err);
        }
        return check_upstream(*upstream_ptr, address);
    });
}

TEST_F(upstream_test, test_bootstrap_timeout) {
    using namespace std::chrono_literals;
    using namespace concat_err_string;
    static constexpr auto timeout = 100ms;
    static constexpr size_t count = 10;
    // Specifying some wrong port instead so that bootstrap DNS timed out for sure
    auto[upstream_ptr, upstream_err] = ag::upstream::address_to_upstream("tls://one.one.one.one", {{"8.8.8.8:555"},
                                                                                                   timeout});
    ASSERT_FALSE(upstream_err) << "Cannot create upstream: " << *upstream_err;
    auto futures = make_indexed_futures(count, [upstream_ptr = upstream_ptr](size_t index) -> ag::err_string {
        infolog(logger(), "Start {}", index);
        ag::utils::timer timer;
        auto req = create_test_message();
        auto[reply, reply_err] = upstream_ptr->exchange(req.get());
        if (!reply_err) {
            return "The upstream must have timed out";
        }
        auto elapsed = timer.elapsed<std::chrono::milliseconds>();
        if (elapsed > 2 * timeout) {
            return AG_FMT("Exchange took more time than the configured timeout: {}", elapsed);
        }
        infolog(logger(), FMT_STRING("Finished {}"), index);
        return std::nullopt;
    });
    ag::err_string err;
    for (size_t i = 0, e = futures.size(); i < e; ++i) {
        auto &future = futures[i];
        auto future_status = future.wait_for(10 * timeout);
        if (future_status == std::future_status::timeout) {
            err += AG_FMT("No response in time for {}", i);
            errlog(logger(), "No response in time for {}", i);
            continue;
        }
        auto result = future.get();
        if (result) {
            err += result;
            errlog(logger(), "Aborted: {}", *result);
        } else {
            infolog(logger(), "Got result from {}", i);
        }
    }
    if (err) {
        ASSERT_FALSE(err) << *err;
    }
}

struct dns_truncated_test : upstream_param_test<std::string_view> {};

static constexpr std::string_view truncated_test_data[]{
    // AdGuard DNS
    "176.103.130.130:53",
    // Google DNS
    "8.8.8.8:53",
    // See the details here: https://github.com/AdguardTeam/AdGuardHome/issues/524
    // AdGuard DNS (DNSCrypt)
    "sdns://AQIAAAAAAAAAFDE3Ni4xMDMuMTMwLjEzMDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20",
    // Cisco OpenDNS (DNSCrypt)
    "sdns://AQAAAAAAAAAADjIwOC42Ny4yMjAuMjIwILc1EUAgbyJdPivYItf9aR6hwzzI1maNDL4Ev6vKQ_t5GzIuZG5zY3J5cHQtY2VydC5vcGVuZG5zLmNvbQ",
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

struct upstream_test_data {
    std::string address;
    std::initializer_list<std::string> bootstrap;
    ag::ip_address_variant server_ip;
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
#if 0
        {} // TODO resolve
#else
        {"1.1.1.1"}
    },
#endif
    {
        "tls://9.9.9.9:853",
#if 0
        {} // TODO resolve
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
#if 0
        {} // TODO resolve
#else
        {"1.1.1.1"}
#endif
    },
#if 0 // TODO FAIL port bug
    {
        "https://dns9.quad9.net:443/dns-query",
        {"8.8.8.8"}
    },
#endif
    {
        "https://dns.cloudflare.com/dns-query",
        {"8.8.8.8:53"}
    },
    {
        "https://dns.google/dns-query",
#if 0
        {} // TODO resolve
#else
        {"8.8.8.8"}
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
        // Cloudflare DNS
        "https://1.1.1.1/dns-query",
#if 0
        {} // TODO resolve
#else
        {"1.1.1.1"}
#endif
    },
};

TEST_F(upstream_test, test_upstreams) {
    parallel_test(test_upstreams_data);
}

static const upstream_test_data upstream_dot_bootstrap_test_data[]{
    {
        "tls://one.one.one.one/",
        {"tls://1.1.1.1"},
    },
    {
        "tls://one.one.one.one/",
        {"https://1.1.1.1/dns-query"},
    },
    {
        "tls://one.one.one.one/",
        // Cisco OpenDNS
        {"sdns://AQAAAAAAAAAADjIwOC42Ny4yMjAuMjIwILc1EUAgbyJdPivYItf9aR6hwzzI1maNDL4Ev6vKQ_t5GzIuZG5zY3J5cHQtY2VydC5vcGVuZG5zLmNvbQ"},
    },
};

TEST_F(upstream_test, test_upstream_dot_bootstrap) {
    parallel_test(upstream_dot_bootstrap_test_data);
}

struct upstream_default_options_test : upstream_param_test<std::string> {};

static const std::string test_upstream_default_options_data[]{
    "tls://1.1.1.1",
    "8.8.8.8",
};

TEST_P(upstream_default_options_test, test_upstream_default_options) {
    const auto &address = GetParam();
    auto[upstream_ptr, upstream_err] = ag::upstream::address_to_upstream(address, {{}, DEFAULT_TIMEOUT});
    ASSERT_FALSE(upstream_err) << "Failed to generate upstream from address " << address << ": " << *upstream_err;
    auto err = check_upstream(*upstream_ptr, address);
    ASSERT_FALSE(err) << *err;
}

INSTANTIATE_TEST_CASE_P(upstream_default_options_test, upstream_default_options_test,
                        testing::ValuesIn(test_upstream_default_options_data));

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
TEST_F(upstream_test, test_upstreams_invalid_bootstrap) {
    parallel_test(test_upstreams_invalid_bootstrap_data);
}

struct upstreams_with_server_ip_test : upstream_param_test<upstream_test_data> {};

// Use invalid bootstrap to make sure it fails if tries to use it
static const std::initializer_list<std::string> invalid_bootstrap{"1.2.3.4:55"};

static const upstream_test_data test_upstreams_with_server_ip_data[]{
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

TEST_F(upstream_test, test_upstreams_with_server_ip) {
    parallel_test(test_upstreams_with_server_ip_data);
}

TEST_F(upstream_test, DISABLED_doh_concurrent_requests) {
    using namespace std::chrono_literals;
    using namespace concat_err_string;
    static constexpr size_t REQUESTS_NUM = 128;
    static constexpr size_t WORKERS_NUM = 16;
    static const ag::upstream::options opts{
        .bootstrap = {"8.8.8.8", "1.1.1.1"},
        .timeout = 5s,
//         .server_ip = ag::ipv4_address_size{104, 19, 199, 29}, // Uncomment for test this server IP
//         .server_ip = ag::ipv6_address_size{0x26, 0x06, 0x47, 0x00, 0x30, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x68, 0x13, 0xc7, 0x1d},  // Uncomment for test this server IP
    };
    auto[upstream_ptr, upstream_err] = ag::upstream::address_to_upstream("https://dns.cloudflare.com/dns-query", opts);
    ASSERT_FALSE(upstream_err) << *upstream_err;
    parallel_test_basic_n(WORKERS_NUM, [upstream_ptr = upstream_ptr](size_t i) -> ag::err_string {
        ag::err_string result_err;
        for (size_t j = 0; j < REQUESTS_NUM; ++j) {
            ag::ldns_pkt_ptr pkt = create_test_message();
            auto[reply, reply_err] = upstream_ptr->exchange(pkt.get());
            if (reply_err) {
                result_err += AG_FMT("DoH i = {} reply error: {}", i, *reply_err);
                continue;
            }
            if (!reply) {
                result_err += "DoH reply is null";
                continue;
            }
            result_err += assert_response(*reply);
        }
        return result_err;
    });
}
