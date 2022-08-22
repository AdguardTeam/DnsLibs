#pragma once

#include <algorithm>
#include <ldns/ldns.h>

#include "dns/common/net_consts.h"

namespace ag::dns {

class DnssecHelpers {
public:
    /**
     * Set DO (DNSSEC OK) flag on request.
     * DO flag asks server to do DNSSEC checks and return valid RRSIGS if server supports DNSSEC.
     * @return true if set, false if was already set before
     */
    static bool set_do_bit(ldns_pkt *request) {
        bool request_has_do_bit = ldns_pkt_edns_do(request);
        // if request has DO bit then we don't change it
        if (request_has_do_bit) {
            return false;
        }

        // https://tools.ietf.org/html/rfc3225#section-3
        ldns_pkt_set_edns_do(request, true);
        // @todo truncate reply to size expected by client
        ldns_pkt_set_edns_udp_size(request, UDP_RECV_BUF_SIZE);

        return true;
    }

    /**
     * Scrub all DNSSEC RRs from the answer and authority sections,
     * except those which are requested
     * @return true if pkt was modified
     */
    static bool scrub_dnssec_rrs(ldns_pkt *pkt) {
        static constexpr ldns_rr_type DNSSEC_RRTYPES[] = {
                LDNS_RR_TYPE_DS, LDNS_RR_TYPE_DNSKEY, LDNS_RR_TYPE_NSEC, LDNS_RR_TYPE_NSEC3, LDNS_RR_TYPE_RRSIG};

        ldns_rr_type qtype = ldns_rr_get_type(ldns_rr_list_rr(ldns_pkt_question(pkt), 0));
        bool modified = false;

        for (ldns_pkt_section section : {LDNS_SECTION_ANSWER, LDNS_SECTION_AUTHORITY}) {
            size_t old_count = ldns_pkt_section_count(pkt, section);
            if (old_count == 0) {
                continue;
            }
            auto *old_section = get_pkt_section(pkt, section);
            auto *new_section = ldns_rr_list_new();
            for (size_t i = 0; i < old_count; ++i) {
                auto *rr = ldns_rr_list_rr(old_section, i);
                ldns_rr_type type = ldns_rr_get_type(rr);
                if ((section == LDNS_SECTION_ANSWER && type == qtype)
                        || std::none_of(
                                std::begin(DNSSEC_RRTYPES), std::end(DNSSEC_RRTYPES), [type](ldns_enum_rr_type extype) {
                                    return extype == type;
                                })) {
                    ldns_rr_list_push_rr(new_section, ldns_rr_clone(rr));
                }
            }
            modified = modified || ldns_rr_list_rr_count(new_section) != old_count;
            ldns_rr_list_deep_free(old_section);
            set_pkt_section(pkt, section, new_section);
            ldns_pkt_set_section_count(pkt, section, ldns_rr_list_rr_count(new_section));
        }

        return modified;
    }

private:
    static ldns_rr_list *get_pkt_section(ldns_pkt *pkt, ldns_pkt_section section) {
        switch (section) {
        case LDNS_SECTION_QUESTION:
            return ldns_pkt_question(pkt);
        case LDNS_SECTION_ANSWER:
            return ldns_pkt_answer(pkt);
        case LDNS_SECTION_AUTHORITY:
            return ldns_pkt_authority(pkt);
        case LDNS_SECTION_ADDITIONAL:
            return ldns_pkt_additional(pkt);
        case LDNS_SECTION_ANY:
        case LDNS_SECTION_ANY_NOQUESTION:
            assert(0);
            break;
        }
        return nullptr;
    }

    static void set_pkt_section(ldns_pkt *pkt, ldns_pkt_section section, ldns_rr_list *new_value) {
        switch (section) {
        case LDNS_SECTION_QUESTION:
            return ldns_pkt_set_question(pkt, new_value);
        case LDNS_SECTION_ANSWER:
            return ldns_pkt_set_answer(pkt, new_value);
        case LDNS_SECTION_AUTHORITY:
            return ldns_pkt_set_authority(pkt, new_value);
        case LDNS_SECTION_ADDITIONAL:
            return ldns_pkt_set_additional(pkt, new_value);
        case LDNS_SECTION_ANY:
        case LDNS_SECTION_ANY_NOQUESTION:
            assert(0);
        }
    }
};

} // namespace ag::dns
