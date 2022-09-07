#include <algorithm>
#include <chrono>
#include <ldns/ldns.h>
#include <memory>

#include "common/utils.h"
#include "dns/net/application_verifier.h"
#include "dns/net/default_verifier.h"
#include "dns/upstream/upstream.h"

#include "dns/upstream/upstream_utils.h"
#include "upstream_plain.h"


namespace ag::dns {

static ldns_pkt_ptr create_message() {
    ldns_pkt *pkt
            = ldns_pkt_query_new(ldns_dname_new_frm_str("ipv4only.arpa."), LDNS_RR_TYPE_A, LDNS_RR_CLASS_IN, LDNS_RD);
    static size_t id = 0;
    ldns_pkt_set_id(pkt, id++);
    return ldns_pkt_ptr(pkt);
}

static coro::Task<ErrString> test_upstream_internal(EventLoop &loop, const UpstreamOptions &opts, bool ipv6_available,
        const OnCertificateVerificationFn &on_certificate_verification, bool offline) {
    co_await loop.co_submit();

    std::unique_ptr<CertificateVerifier> cert_verifier;
    if (on_certificate_verification != nullptr) {
        cert_verifier = std::make_unique<ApplicationVerifier>(on_certificate_verification);
    } else {
        cert_verifier = std::make_unique<DefaultVerifier>();
    }
    SocketFactory socket_factory({
            .loop = loop,
            .verifier = std::move(cert_verifier),
    });
    UpstreamFactory upstream_factory({loop, &socket_factory, ipv6_available});
    auto upstream_result = upstream_factory.create_upstream(opts);
    if (upstream_result.has_error()) {
        co_return upstream_result.error()->str();
    }
    UpstreamPtr &upstream = upstream_result.value();
    if (offline) {
        co_return std::nullopt;
    }
    auto reply = co_await upstream->exchange(create_message().get());
    upstream.reset();
    if (reply.has_error()) {
        co_return reply.error()->str();
    }
    if (ldns_rr_list_rr_count(ldns_pkt_answer(reply->get())) == 0) {
        co_return "DNS upstream returned reply with wrong number of answers";
    }
    // Everything else is supposed to be success
    co_return std::nullopt;
}

ErrString test_upstream(const UpstreamOptions &opts, bool ipv6_available,
        const OnCertificateVerificationFn &on_certificate_verification, bool offline) {
    EventLoopPtr loop = EventLoop::create();
    loop->start();
    ErrString ret =
            coro::to_future(test_upstream_internal(*loop, opts, ipv6_available, on_certificate_verification, offline))
                    .get();
    loop->stop();
    loop->join();
    return ret;
}

} // namespace ag::dns
