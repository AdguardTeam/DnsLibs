#include "upstream_system.h"
#include "common/logger.h"
#include <net/if.h>

#ifdef __ANDROID__
#include <android/multinetwork.h>
#ifdef USE_INTERFACE_NAMES_IN_SYSTEM_UPSTREAM
#include "android_context_manager.h"
#endif
#endif

namespace ag::dns {

static ag::Logger g_log{"SystemUpstream"};

SystemUpstream::SystemUpstream(const UpstreamOptions &opts, const UpstreamFactoryConfig &config)
        : Upstream(opts, config)
        , m_log(AG_FMT("System upstream ({})", opts.address)) {
    const auto POS = opts.address.find("://");
    if (POS != std::string::npos) {
        m_interface = opts.address.substr(POS + 3);
    }
}

Error<Upstream::InitError> SystemUpstream::init() {
#ifdef __ANDROID__
    net_handle_t network_handle = NETWORK_UNSPECIFIED;

    if (!m_interface.empty()) {
#ifdef USE_INTERFACE_NAMES_IN_SYSTEM_UPSTREAM
        auto handle_opt = AndroidContextManager::get_network_handle_for_interface(m_interface);
        if (!handle_opt.has_value()) {
            return make_error(InitError::AE_INVALID_ADDRESS, AG_FMT("Invalid interface name: {}", m_interface));
        }
        tracelog(g_log, "Resolved interface '{}' to network handle: {}", m_interface, handle_opt.value());
        network_handle = handle_opt.value();
#else
        return make_error(InitError::AE_INVALID_ADDRESS,
                AG_FMT("Interface names not supported in this build (interface: {})", m_interface));
#endif
    }

    auto result = SystemResolver::create(&config().loop, config().timeout, network_handle);
#else
    uint32_t if_index = 0;
    if (!m_interface.empty()) {
        if_index = if_nametoindex(m_interface.c_str());
        if (if_index == 0) {
            return make_error(InitError::AE_INVALID_ADDRESS, AG_FMT("Invalid interface name: {}", m_interface));
        }
    }

    auto result = SystemResolver::create(&config().loop, config().timeout, if_index);
#endif
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
        ldns_pkt_set_ancount(reply_pkt, ldns_rr_list_rr_count(result.value().get()));
        ldns_pkt_set_answer(reply_pkt, ldns_rr_list_clone(result.value().get()));
        ldns_pkt_set_rcode(reply_pkt, LDNS_RCODE_NOERROR);
        co_return ldns_pkt_ptr{reply_pkt};
    }

    switch (result.error()->value()) {
    case SystemResolverError::AE_DOMAIN_NOT_FOUND:
        ldns_pkt_set_rcode(reply_pkt, LDNS_RCODE_NXDOMAIN);
        co_return ldns_pkt_ptr{reply_pkt};
    case SystemResolverError::AE_RECORD_NOT_FOUND:
        ldns_pkt_set_rcode(reply_pkt, LDNS_RCODE_NOERROR);
        co_return ldns_pkt_ptr{reply_pkt};
    default:
        assert(0);
        co_return ldns_pkt_ptr{};
    }
}
} // namespace ag::dns
