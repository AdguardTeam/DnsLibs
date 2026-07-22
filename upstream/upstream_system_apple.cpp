#include <net/if.h>

#include "common/logger.h"
#include "upstream_system.h"

namespace ag::dns {

SystemUpstream::SystemUpstream(const UpstreamOptions &opts, const UpstreamFactoryConfig &config)
        : Upstream(opts, config)
        , m_log(AG_FMT("System upstream ({})", opts.address))
        , m_interface(interface_from_address(opts.address)) {
}

SystemUpstream::~SystemUpstream() = default;

Error<Upstream::InitError> SystemUpstream::init() {
    uint32_t if_index = 0;
    if (!m_interface.empty()) {
        if_index = if_nametoindex(m_interface.c_str());
        if (if_index == 0) {
            return make_error(InitError::AE_INVALID_ADDRESS, AG_FMT("Invalid interface name: {}", m_interface));
        }
    }

    auto result = SystemResolver::create(&config().loop, config().timeout, if_index);
    if (result.has_error()) {
        return make_error(InitError::AE_SYSTEMRESOLVER_INIT_FAILED,
                ErrorCodeToString<SystemResolverError>{}(result.error().get()->value()));
    }

    m_resolver = std::move(result.value());
    return {};
}

coro::Task<Upstream::ExchangeResult> SystemUpstream::exchange(const ldns_pkt *request_pkt, const DnsMessageInfo *info) {
    const ldns_rr *question = ldns_rr_list_rr(ldns_pkt_question(request_pkt), 0);
    auto domain = AllocatedPtr<char>(ldns_rdf2str(ldns_rr_owner(question)));
    if (!domain) {
        co_return make_error(DnsError::AE_INTERNAL_ERROR, "Failed to get domain name from question");
    }
    const ldns_rr_type RR_TYPE = ldns_rr_get_type(question);

    // DNSService gives us the records only, not the raw reply, so the reply has to be assembled by hand.
    auto result = co_await m_resolver->resolve(domain.get(), RR_TYPE);
    if (result.has_error()) {
        auto &error = result.error();
        if (error->value() != SystemResolverError::AE_DOMAIN_NOT_FOUND
                && error->value() != SystemResolverError::AE_RECORD_NOT_FOUND) {
            if (error->value() == SystemResolverError::AE_TIMED_OUT) {
                co_return make_error(DnsError::AE_TIMED_OUT, ErrorCodeToString<SystemResolverError>{}(error->value()));
            }
            co_return make_error(DnsError::AE_INTERNAL_ERROR, ErrorCodeToString<SystemResolverError>{}(error->value()));
        }
    }

    ldns_pkt *reply_pkt = ldns_pkt_clone(request_pkt);
    ldns_pkt_set_qr(reply_pkt, true);
    ldns_pkt_set_aa(reply_pkt, false);
    ldns_pkt_set_rd(reply_pkt, true);
    ldns_pkt_set_ra(reply_pkt, true);
    ldns_pkt_set_ad(reply_pkt, false);
    ldns_pkt_set_cd(reply_pkt, false);

    if (result.has_value()) {
        size_t record_count = ldns_rr_list_rr_count(result.value().get());
        ldns_pkt_set_ancount(reply_pkt, record_count);
        ldns_pkt_set_answer(reply_pkt, ldns_rr_list_clone(result.value().get()));
        ldns_pkt_set_rcode(reply_pkt, LDNS_RCODE_NOERROR);

        if (record_count == 0) {
            ldns_pkt_push_rr(reply_pkt, LDNS_SECTION_AUTHORITY, create_soa(request_pkt));
        }

        co_return ldns_pkt_ptr{reply_pkt};
    }

    switch (result.error()->value()) {
    case SystemResolverError::AE_DOMAIN_NOT_FOUND:
        ldns_pkt_set_rcode(reply_pkt, LDNS_RCODE_NXDOMAIN);
        ldns_pkt_push_rr(reply_pkt, LDNS_SECTION_AUTHORITY, create_soa(request_pkt));
        co_return ldns_pkt_ptr{reply_pkt};
    case SystemResolverError::AE_RECORD_NOT_FOUND:
        ldns_pkt_set_rcode(reply_pkt, LDNS_RCODE_NOERROR);
        ldns_pkt_push_rr(reply_pkt, LDNS_SECTION_AUTHORITY, create_soa(request_pkt));
        co_return ldns_pkt_ptr{reply_pkt};
    default:
        assert(0);
        co_return ldns_pkt_ptr{};
    }
}

} // namespace ag::dns
