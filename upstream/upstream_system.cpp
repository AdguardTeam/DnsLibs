#include "upstream_system.h"
#include <net/if.h>

namespace ag::dns {

SystemUpstream::SystemUpstream(const UpstreamOptions &opts, const UpstreamFactoryConfig &config)
        : Upstream(opts, config)
        , m_log(AG_FMT("System upstream ({})", opts.address)) {
    const auto POS = opts.address.find("://");
    if (POS != std::string::npos) {
        m_interface = opts.address.substr(POS + 3);
    }
}

Error<Upstream::InitError> SystemUpstream::init() {
    uint32_t if_index = 0;
    if (!m_interface.empty()) {
        if_index = if_nametoindex(m_interface.c_str());
        if (if_index == 0) {
            return make_error(InitError::AE_INVALID_ADDRESS, AG_FMT("Invalid interface name: {}", m_interface));
        }
    }

    auto result = SystemResolver::create(&config().loop, if_index);
    if (result.has_error()) {
        return make_error(InitError::AE_SYSTEMRESOLVER_INIT_FAILED,
                ErrorCodeToString<SystemResolverError>{}(result.error().get()->value()));
    }

    m_resolver = std::move(result.value());
    return {};
}

coro::Task<Upstream::ExchangeResult> SystemUpstream::exchange(const ldns_pkt *request_pkt, const DnsMessageInfo *info) {
    const ldns_rr *question = ldns_rr_list_rr(ldns_pkt_question(request_pkt), 0);
    const std::string domain = ldns_rdf2str(ldns_rr_owner(question));
    const ldns_rr_type RR_TYPE = ldns_rr_get_type(question);

    auto result = co_await m_resolver->resolve(domain, RR_TYPE);
    if (result.has_error() && result.error()->value() != SystemResolverError::AE_DOMAIN_NOT_FOUND) {
        co_return make_error(
                DnsError::AE_BAD_RESPONSE, ErrorCodeToString<SystemResolverError>{}(result.error().get()->value()));
    }

    ldns_pkt *reply_pkt = ldns_pkt_clone(request_pkt);
    ldns_pkt_set_qr(reply_pkt, true);
    ldns_pkt_set_aa(reply_pkt, false);
    ldns_pkt_set_rd(reply_pkt, true);
    ldns_pkt_set_ra(reply_pkt, true);
    ldns_pkt_set_ad(reply_pkt, false);
    ldns_pkt_set_cd(reply_pkt, false);

    if (result.has_value()) {
        ldns_pkt_set_ancount(reply_pkt, ldns_rr_list_rr_count(result.value().get()));
        ldns_pkt_set_answer(reply_pkt, ldns_rr_list_clone(result.value().get()));
        ldns_pkt_set_rcode(reply_pkt, LDNS_RCODE_NOERROR);
    }else {
        ldns_pkt_set_rcode(reply_pkt, LDNS_RCODE_NXDOMAIN);
    }

    co_return ldns_pkt_ptr{reply_pkt};
}
} // namespace ag::dns
