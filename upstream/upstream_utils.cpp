#include "upstream/upstream_utils.h"
#include "common/utils.h"
#include "net/application_verifier.h"
#include "net/default_verifier.h"
#include "upstream/upstream.h"
#include "upstream_plain.h"
#include <algorithm>
#include <chrono>
#include <ldns/ldns.h>
#include <memory>

namespace ag {

static ldns_pkt_ptr create_message() {
    ldns_pkt *pkt
            = ldns_pkt_query_new(ldns_dname_new_frm_str("ipv4only.arpa."), LDNS_RR_TYPE_A, LDNS_RR_CLASS_IN, LDNS_RD);
    static size_t id = 0;
    ldns_pkt_set_id(pkt, id++);
    return ldns_pkt_ptr(pkt);
}

ErrString test_upstream(const UpstreamOptions &opts, bool ipv6_available,
        const OnCertificateVerificationFn &on_certificate_verification, bool offline) {
    std::unique_ptr<CertificateVerifier> cert_verifier;
    if (on_certificate_verification != nullptr) {
        cert_verifier = std::make_unique<ApplicationVerifier>(on_certificate_verification);
    } else {
        cert_verifier = std::make_unique<DefaultVerifier>();
    }
    SocketFactory socket_factory({nullptr, std::move(cert_verifier)});
    UpstreamFactory upstream_factory({&socket_factory, ipv6_available});
    auto [upstream_ptr, upstream_err] = upstream_factory.create_upstream(opts);
    if (upstream_err) {
        return upstream_err;
    }
    if (offline) {
        return std::nullopt;
    }
    auto [reply, exchange_err] = upstream_ptr->exchange(create_message().get());
    if (exchange_err) {
        return exchange_err;
    }
    if (ldns_rr_list_rr_count(ldns_pkt_answer(reply.get())) == 0) {
        return "DNS upstream returned reply with wrong number of answers";
    }
    // Everything else is supposed to be success
    return std::nullopt;
}

} // namespace ag
