#include <upstream.h>
#include <ldns/ldns.h>

static inline bool test_ipv6_connectivity() {
    ag::ldns_pkt_ptr query{
            ldns_pkt_query_new(
                    ldns_dname_new_frm_str("google.com"),
                    LDNS_RR_TYPE_A, LDNS_RR_CLASS_IN, LDNS_RD)};

    ag::socket_factory socket_factory({});
    ag::upstream_factory upstream_factory({ &socket_factory });

    // Google public DNS
    for (auto &addr : {"2001:4860:4860::8888", "2001:4860:4860::8844"}) {
        auto r = upstream_factory.create_upstream({ addr, {}, std::chrono::seconds{1}, {} });
        if (r.error.has_value()) {
            return false;
        }
        auto result = r.upstream->exchange(query.get());
        if (!result.error && LDNS_RCODE_NOERROR == ldns_pkt_get_rcode(result.packet.get())) {
            return true;
        }
    }

    return false;
}
