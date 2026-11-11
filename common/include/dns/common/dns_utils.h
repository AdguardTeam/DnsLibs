#pragma once

#include <cassert>
#include <cstdint>
#include <ctime>
#include <memory>
#include <optional>

#include <ldns/ldns.h>

#include "common/defs.h"
#include "common/net_utils.h"

namespace ag::dns {

/** Additional info about the DNS message */
struct DnsMessageInfo {
    /** The subset of \ref DnsProxySettings available for overriding on a specific message */
    struct ProxySettingsOverrides {
        /** \ref DnsProxySettings.block_ech, has no effect if `nullopt` */
        std::optional<bool> block_ech;
    };

    /** Transport protocol over which the message was received */
    utils::TransportProtocol proto = utils::TP_UDP;
    /** Socket address of the peer from which the message was received */
    SocketAddress peername;
    /** Overridden settings */
    ProxySettingsOverrides settings_overrides;
    /**
     * Indicates whether the caller wishes to filter this message transparently.
     *
     * If `false`, the proxy processes the message in a usual way, and the final response is returned.
     *
     * If `true`, and the message is a query, the proxy won't pass it to the upstream (it may still make an upstream
     * request in order to process CNAME-rewrites, for example), instead, it will return the processed request, which
     * the caller should pass to the upstream, or a generated response, which the caller should pass to the client.
     *
     * If `true`, and this message is a response, the proxy will process the message as if it was received from an
     * upstream, and return the processed response, which the caller should pass to the client.
     *
     * When filtering transparently, the proxy will NOT perform DNS64 synthesis.
     */
    bool transparent = false;
};

/** Return `nullptr` if `opt.has_value() == false`, or `std::addressof(opt.value())` if `opt.has_value() == true`. */
template <typename T>
T *opt_as_ptr(std::optional<T> &opt) {
    if (opt.has_value()) {
        return std::addressof(*opt);
    }
    return nullptr;
}

/** Return `true` if `pkt` is a DNS response, `false` in all other cases. */
inline bool is_response(Uint8View pkt) {
    if (pkt.size() >= 3) {
        // Return the value of the QR bit
        return pkt[2] & 0x80; // NOLINT(*-avoid-magic-numbers)
    }
    return false;
}

/** Default TTL of a synthesized SOA record. */
inline constexpr uint32_t SOA_TTL_DEFAULT = 300;

/** Default retry value of a synthesized SOA record. */
inline constexpr uint32_t SOA_RETRY_DEFAULT = 900;

namespace detail {

inline ldns_rdf *make_soa_mbox(const ldns_pkt *request) {
    const ldns_rr *question = ldns_rr_list_rr(ldns_pkt_question(request), 0);

    ldns_rdf *owner = ldns_rr_owner(question);

    UniquePtr<ldns_rdf, &ldns_rdf_deep_free> hostmaster{ldns_dname_new_frm_str("hostmaster.")};
    UniquePtr<ldns_rdf, &ldns_rdf_deep_free> mbox{ldns_dname_cat_clone(hostmaster.get(), owner)};
    if (mbox) {
        if (auto valid = AllocatedPtr<char>{ldns_rdf2str(mbox.get())}) {
            return mbox.release();
        }
    }

    return hostmaster.release();
}

} // namespace detail

/**
 * Creates a SOA record for the authority section of a negative response.
 * @param request The request to take the owner name from.
 * @param ttl_secs The SOA TTL.
 * @param retry_secs The SOA retry value.
 * @return A newly allocated SOA record.
 */
// Taken from AdGuardHome/dnsforward.go/genSOA
inline ldns_rr *create_soa(
        const ldns_pkt *request, uint32_t ttl_secs = SOA_TTL_DEFAULT, uint32_t retry_secs = SOA_RETRY_DEFAULT) {
    const ldns_rr *question = ldns_rr_list_rr(ldns_pkt_question(request), 0);

    ldns_rr *soa = ldns_rr_new();
    assert(soa != nullptr);
    ldns_rr_set_owner(soa, ldns_rdf_clone(ldns_rr_owner(question)));
    ldns_rr_set_ttl(soa, ttl_secs);
    ldns_rr_set_type(soa, LDNS_RR_TYPE_SOA);
    ldns_rr_set_class(soa, LDNS_RR_CLASS_IN);
    // fill soa rdata
    ldns_rr_push_rdf(soa, ldns_dname_new_frm_str("fake-for-negative-caching.adguard.com."));  // MNAME
    ldns_rr_push_rdf(soa, detail::make_soa_mbox(request));                                    // RNAME
    ldns_rr_push_rdf(soa, ldns_native2rdf_int32(LDNS_RDF_TYPE_TIME, time(nullptr) + 100500)); // SERIAL
    ldns_rr_push_rdf(soa, ldns_native2rdf_int32(LDNS_RDF_TYPE_PERIOD, 1800));                 // REFRESH
    ldns_rr_push_rdf(soa, ldns_native2rdf_int32(LDNS_RDF_TYPE_PERIOD, retry_secs));           // RETRY
    ldns_rr_push_rdf(soa, ldns_native2rdf_int32(LDNS_RDF_TYPE_PERIOD, 604800));               // EXPIRE
    ldns_rr_push_rdf(soa, ldns_native2rdf_int32(LDNS_RDF_TYPE_PERIOD, 86400));                // MINIMUM
    return soa;
}

} // namespace ag::dns
