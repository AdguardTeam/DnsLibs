#include <ctime>

#include "upstream_system.h"

namespace ag::dns {

static constexpr uint32_t DEFAULT_SOA_TTL = 300;

// The constructor and the destructor are defined in the platform-specific files: on Android
// they need the definition of SystemUpstream::Impl, which only that file has.

std::string SystemUpstream::interface_from_address(std::string_view address) {
    const auto POS = address.find("://");
    return POS != std::string_view::npos ? std::string(address.substr(POS + 3)) : std::string{};
}

// Based on ResponseHelpers::create_soa()
ldns_rr *SystemUpstream::create_soa(const ldns_pkt *request) {
    const ldns_rr *question = ldns_rr_list_rr(ldns_pkt_question(request), 0);

    ldns_rr *soa = ldns_rr_new();
    ldns_rr_set_owner(soa, ldns_rdf_clone(ldns_rr_owner(question)));
    ldns_rr_set_ttl(soa, DEFAULT_SOA_TTL);
    ldns_rr_set_type(soa, LDNS_RR_TYPE_SOA);
    ldns_rr_set_class(soa, LDNS_RR_CLASS_IN);

    ldns_rr_push_rdf(soa, ldns_dname_new_frm_str("fake-for-negative-caching.adguard.com."));
    ldns_rr_push_rdf(soa, ldns_dname_new_frm_str("hostmaster."));
    ldns_rr_push_rdf(soa, ldns_native2rdf_int32(LDNS_RDF_TYPE_TIME, time(nullptr)));
    ldns_rr_push_rdf(soa, ldns_native2rdf_int32(LDNS_RDF_TYPE_PERIOD, 1800));
    ldns_rr_push_rdf(soa, ldns_native2rdf_int32(LDNS_RDF_TYPE_PERIOD, 900));
    ldns_rr_push_rdf(soa, ldns_native2rdf_int32(LDNS_RDF_TYPE_PERIOD, 604800));
    ldns_rr_push_rdf(soa, ldns_native2rdf_int32(LDNS_RDF_TYPE_PERIOD, 86400));

    return soa;
}

} // namespace ag::dns
