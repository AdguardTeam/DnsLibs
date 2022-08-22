#include "common/defs.h"
#include "common/utils.h"
#include "dns_forwarder_utils.h"

namespace ag::dns {

std::string DnsForwarderUtils::rr_list_to_string(const ldns_rr_list *rr_list) {
    if (rr_list == nullptr) {
        return {};
    }
    AllocatedPtr<char> answer(ldns_rr_list2str(rr_list));
    if (answer == nullptr) {
        return {};
    }
    std::string_view answer_view = answer.get();
    std::string out;
    out.reserve(answer_view.size());
    for (auto record : ag::utils::split_by(answer_view, '\n')) {
        auto record_parts = ag::utils::split_by(record, '\t');
        auto it = record_parts.begin();
        if (record_parts.size() >= 4) {
            it++; // Skip owner
            it++; // Skip ttl
            it++; // Skip class
            out += *it++; // Add type
            out += ',';
            // Add serialized RDFs
            while (it != record_parts.end()) {
                out += ' ';
                out += *it++;
            }
            out += '\n';
        }
    }
    return out;
}

} // namespace ag::dns
