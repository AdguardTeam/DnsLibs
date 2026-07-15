#pragma once

#include <functional>
#include <ldns/ldns.h>
#include <string>
#include <utility>

#include "dns/upstream/upstream.h"
#include "dns_test_helpers.h"

namespace ag::test {

// Implements dns::Upstream with no network I/O. exchange() either delegates to
// a user-supplied handler or returns a canned A-record response. Use it as a
// programmatic stand-in for tests that don't need a real socket.
class MockUpstream : public ag::dns::Upstream {
public:
    using ExchangeResult = ag::dns::Upstream::ExchangeResult;
    using ExchangeHandler = std::function<ExchangeResult(const ldns_pkt *, const ag::dns::DnsMessageInfo *)>;

    MockUpstream(ag::dns::UpstreamOptions opts, ag::dns::UpstreamFactoryConfig config)
            : Upstream(std::move(opts), std::move(config)) {
    }

    ag::Error<InitError> init() override {
        return nullptr;
    }

    ag::coro::Task<ExchangeResult> exchange(
            const ldns_pkt *request, const ag::dns::DnsMessageInfo *info = nullptr) override {
        if (m_handler) {
            co_return m_handler(request, info);
        }
        co_return default_response(request);
    }

    // When set, exchange() delegates to this instead of default_response().
    ExchangeHandler m_handler;

    // A canned reply for `request`: clones it, sets QR=1/RA=1/NOERROR, and
    // appends one A answer (1.2.3.4) echoing the request's qname.
    static ExchangeResult default_response(const ldns_pkt *request) {
        if (request == nullptr) {
            return make_dns_error(ag::dns::DnsError::AE_DECODE_ERROR, "No request provided");
        }
        ag::dns::ldns_pkt_ptr reply = make_base_reply(*request);
        const ldns_rr *question = ldns_rr_list_rr(ldns_pkt_question(request), 0);
        if (question == nullptr) {
            return make_dns_error(ag::dns::DnsError::AE_BAD_RESPONSE, "Request has no question");
        }
        add_a_answer(reply.get(), question);
        return reply;
    }

    // Named make_dns_error (not make_error) because native_libs_common defines
    // make_error as a macro: a member named make_error would be macro-expanded
    // at its declaration and fail to compile.
    static ExchangeResult make_dns_error(ag::dns::DnsError code, std::string msg) {
        return make_error(code, std::move(msg));
    }
};

} // namespace ag::test
