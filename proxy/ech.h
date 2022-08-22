#pragma once

#include <ldns/ldns.h>

#include "common/defs.h"
#include "dns/common/dns_defs.h"
#include "dns/common/net_consts.h"

namespace ag::dns {

class EchHelpers {
public:
    /**
     * Remove the "ech" parameter from the SvcParams part of any SVCB/HTTPS record contained in `response`
     */
    static bool remove_ech_svcparam(ldns_pkt *response) {
        bool removed = false;
        for (size_t i = 0; i < ldns_pkt_ancount(response); ++i) {
            ldns_rr *rr = ldns_rr_list_rr(ldns_pkt_answer(response), i);

            if (auto type = ldns_rr_get_type(rr);
                    (type != LDNS_RR_TYPE_SVCB && type != LDNS_RR_TYPE_HTTPS) || (ldns_rr_rd_count(rr) != 3)) {
                continue;
            }

            ldns_rdf *params = ldns_rr_rdf(rr, 2);

            if (ldns_rdf_get_type(params) != LDNS_RDF_TYPE_SVCPARAMS) {
                continue;
            }

            uint8_t *current_param_start = nullptr;
            uint16_t key, len;
            ag::Uint8View params_tail = {ldns_rdf_data(params), ldns_rdf_size(params)};
            while (params_tail.size() >= sizeof(key)) {
                current_param_start = (uint8_t *) params_tail.data();

                std::memcpy(&key, params_tail.data(), sizeof(key));
                params_tail.remove_prefix(sizeof(key));

                if (params_tail.size() < sizeof(len)) {
                    break;
                }

                std::memcpy(&len, params_tail.data(), sizeof(len));
                params_tail.remove_prefix(sizeof(len));

                key = ntohs(key);
                len = ntohs(len);

                if (params_tail.size() < len) {
                    break;
                }

                params_tail.remove_prefix(len);

                if (key == LDNS_SVCPARAM_KEY_ECHCONFIG) {
                    removed = true;
                    std::memmove(current_param_start, params_tail.data(), params_tail.size());
                    ldns_rdf_set_size(params, ldns_rdf_size(params) - sizeof(key) - sizeof(len) - len);
                    break;
                }
            }
        }
        return removed;
    }
};

} // namespace ag::dns
