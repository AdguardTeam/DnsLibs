#pragma once

// Generic DNS packet construction helpers for tests. These functions wrap
// verbose ldns C-API calls into small, composable utilities so that test
// handlers can build canned responses with minimal boilerplate.
//
// Usage: include this header from any test target that already links against
// ldns and is configured with the `common/test_helpers` include directory.

#include <ldns/ldns.h>
#include <string>

#include "dns/common/dns_defs.h"

namespace ag::test {

// Build a NOERROR reply that echoes the request's question section, with
// QR=1, RA=1, and an empty answer section. This is the usual starting point
// for canned upstream handlers.
inline ag::dns::ldns_pkt_ptr make_base_reply(const ldns_pkt &req) {
    ag::dns::ldns_pkt_ptr reply{ldns_pkt_clone(&req)};
    ldns_pkt_set_qr(reply.get(), true);
    ldns_pkt_set_ra(reply.get(), true);
    ldns_pkt_set_rcode(reply.get(), LDNS_RCODE_NOERROR);
    return reply;
}

// Append an A answer (1.2.3.4) echoing the request's qname to `reply`.
inline void add_a_answer(ldns_pkt *reply, const ldns_rr *question) {
    ldns_rr *answer = ldns_rr_new();
    ldns_rr_set_owner(answer, ldns_rdf_clone(ldns_rr_owner(question)));
    ldns_rr_set_ttl(answer, 300);
    ldns_rr_set_type(answer, LDNS_RR_TYPE_A);
    ldns_rr_set_class(answer, LDNS_RR_CLASS_IN);
    ldns_rr_push_rdf(answer, ldns_rdf_new_frm_str(LDNS_RDF_TYPE_A, "1.2.3.4"));
    ldns_pkt_push_rr(reply, LDNS_SECTION_ANSWER, answer);
}

// Append an RR built from an ldns presentation string (e.g.
// "example.org. 300 IN A 1.2.3.4") to `reply`'s answer section.
// The string must already contain the owner name. Returns true on success.
inline bool add_rr_from_str(ldns_pkt *reply, const std::string &rr_str) {
    ldns_rr *rr = nullptr;
    if (ldns_rr_new_frm_str(&rr, rr_str.c_str(), 0, nullptr, nullptr) != LDNS_STATUS_OK || rr == nullptr) {
        return false;
    }
    ldns_pkt_push_rr(reply, LDNS_SECTION_ANSWER, rr);
    return true;
}

// Append a synthetic RRSIG RR covering `type_covered`, owned by `owner`.
// The signature data is fake; tests only check for RRSIG presence/absence,
// not cryptographic validity.
inline void add_rrsig(ldns_pkt *reply, const ldns_rdf *owner, ldns_rr_type type_covered) {
    AllocatedPtr<char> owner_str{ldns_rdf2str(owner)};
    AllocatedPtr<char> type_str{ldns_rr_type2str(type_covered)};
    std::string rr_str =
            AG_FMT("{} 300 IN RRSIG {} 8 2 300 20260101000000 20260101000000 12345 {} dGVzdA==", owner_str.get(),
                    type_str.get(), owner_str.get());
    add_rr_from_str(reply, rr_str);
}

} // namespace ag::test
