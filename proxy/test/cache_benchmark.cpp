#include <dnsproxy.h>
#include <ag_utils.h>
#include <ldns/ldns.h>
#include <chrono>
#include <atomic>
#include <thread>
#include <iostream>

static constexpr int N_REQUESTS = 1000000;
static constexpr int N_THREADS = 12;

/**
 * @return The run time of f(args...) in seconds.
 */
template <typename Func, typename... Args>
double time(Func &&f, Args &&... args) {
    using namespace std::chrono;
    auto start = high_resolution_clock::now();
    std::forward<Func>(f)(std::forward<Args>(args)...);
    auto end = high_resolution_clock::now();
    return duration_cast<nanoseconds>(end - start).count() / 1e9;
}

int main() {
    ag::dnsproxy_settings settings = ag::dnsproxy_settings::get_default();
    ag::dnsproxy proxy;
    if (!proxy.init(settings, {})) {
        return 1;
    }

    ag::utils::scope_exit se([&proxy]() { proxy.deinit(); });

    ag::ldns_pkt_ptr reqpkt(
            ldns_pkt_query_new(
                    ldns_dname_new_frm_str("google.com"),
                    LDNS_RR_TYPE_A,
                    LDNS_RR_CLASS_IN,
                    LDNS_RD));
    if (!reqpkt) {
        return 1;
    }

    std::unique_ptr<ldns_buffer, ag::ftor<ldns_buffer_free>> buf(ldns_buffer_new(512));
    if (ldns_pkt2buffer_wire(buf.get(), reqpkt.get()) != LDNS_STATUS_OK) {
        return 1;
    }

    std::atomic_int c{0};
    double t = time([&]() {
        std::thread tt[N_THREADS];
        for (auto &t : tt) {
            t = std::thread([&]() {
                int j;
                for (j = 0; j < N_REQUESTS / N_THREADS; ++j) {
                    const auto r = proxy.handle_message({ldns_buffer_at(buf.get(), 0),
                                                         ldns_buffer_position(buf.get())});
                    if (r.empty()) {
                        std::cout << "Error: empty response!\n";
                        break;
                    }
                }
                c.fetch_add(j);
            });
        }
        for (auto &t : tt) {
            t.join();
        }
    });

    std::cout << "reqs: " << c << "\ntime: " << t << " s\n" << (c / t) << " req/s\n";

    return 0;
}
