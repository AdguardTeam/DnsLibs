#include <algorithm>
#include <chrono>
#include <memory>
#include <ldns/ldns.h>
#include <ag_utils.h>
#include <application_verifier.h>
#include <default_verifier.h>
#include <upstream.h>
#include "upstream_utils.h"
#include "upstream_plain.h"

static ag::ldns_pkt_ptr create_message() {
    ldns_pkt *pkt = ldns_pkt_query_new(ldns_dname_new_frm_str("ipv4only.arpa."), LDNS_RR_TYPE_A, LDNS_RR_CLASS_IN,
                                       LDNS_RD);
    static size_t id = 0;
    ldns_pkt_set_id(pkt, id++);
    return ag::ldns_pkt_ptr(pkt);
}

ag::err_string ag::test_upstream(const upstream_options &opts,
                                 const on_certificate_verification_function &on_certificate_verification) {
    std::unique_ptr<ag::certificate_verifier> cert_verifier;
    if (on_certificate_verification != nullptr) {
        cert_verifier = std::make_unique<ag::application_verifier>(on_certificate_verification);
    } else {
        cert_verifier = std::make_unique<ag::default_verifier>();
    }
    bool bootstrap_ipv6 = test_ipv6_connectivity();
    ag::upstream_factory upstream_factory({cert_verifier.get(), bootstrap_ipv6});
    auto[upstream_ptr, upstream_err] = upstream_factory.create_upstream(opts);
    if (upstream_err) {
        return upstream_err;
    }
    auto[reply, exchange_err] = upstream_ptr->exchange(create_message().get());
    if (exchange_err) {
        return exchange_err;
    }
    if (ldns_rr_list_rr_count(ldns_pkt_answer(reply.get())) == 0) {
        return "DNS upstream returned reply with wrong number of answers";
    }
    // Everything else is supposed to be success
    return std::nullopt;
}

bool ag::test_ipv6_connectivity() {
    ag::ldns_pkt_ptr query{
            ldns_pkt_query_new(
                    ldns_dname_new_frm_str("google.com"),
                    LDNS_RR_TYPE_A, LDNS_RR_CLASS_IN, LDNS_RD)};

    // Google public DNS
    for (auto &addr : {"2001:4860:4860::8888", "2001:4860:4860::8844"}) {
        ag::plain_dns upstream({addr, {}, std::chrono::seconds{1}, {}}, {nullptr});
        auto result = ((ag::upstream *) &upstream)->exchange(query.get());
        if (!result.error && LDNS_RCODE_NOERROR == ldns_pkt_get_rcode(result.packet.get())) {
            return true;
        }
    }

    return false;
}
