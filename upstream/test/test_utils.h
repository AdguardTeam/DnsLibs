#include <ldns/ldns.h>

#include "common/coro.h"
#include "dns/upstream/upstream.h"

static ag::coro::Task<bool> co_test_ipv6_connectivity(ag::dns::EventLoop &loop) {
    co_await loop.co_submit();
    ag::dns::ldns_pkt_ptr query{
            ldns_pkt_query_new(
                    ldns_dname_new_frm_str("google.com"),
                    LDNS_RR_TYPE_A, LDNS_RR_CLASS_IN, LDNS_RD)};

    ag::dns::SocketFactory socket_factory({loop});
    ag::dns::UpstreamFactory upstream_factory({loop, &socket_factory});

    // Google public DNS
    for (auto &addr : {"2001:4860:4860::8888", "2001:4860:4860::8844"}) {
        auto r = upstream_factory.create_upstream({ addr, {}, ag::Secs{1}, {} });
        if (r.has_error()) {
            co_return false;
        }
        auto result = co_await r.value()->exchange(query.get());
        if (!result.has_error() && LDNS_RCODE_NOERROR == ldns_pkt_get_rcode(result->get())) {
            co_return true;
        }
    }

    co_return false;
}

static bool test_ipv6_connectivity() {
    ag::dns::EventLoopPtr loop = ag::dns::EventLoop::create();
    loop->start();
    bool avail = ag::coro::to_future(co_test_ipv6_connectivity(*loop)).get();
    loop->stop();
    loop->join();
    return avail;
}
