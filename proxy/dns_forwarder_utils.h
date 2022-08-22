#pragma once

#include <ldns/ldns.h>
#include <string>

namespace ag::dns {

class DnsForwarderUtils {
public:
    /**
     * Format RR list as user-friendly string:
     * <Type>, <RDFs, space separated>\n
     * e.g.:
     * A, 1.2.3.4
     * AAAA, 12::34
     * CNAME, google.com.
     */
    static std::string rr_list_to_string(const ldns_rr_list *rr_list);
};

} // namespace ag::dns
