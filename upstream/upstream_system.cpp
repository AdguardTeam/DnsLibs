#include "upstream_system.h"
#include "dns/upstream/upstream_utils.h"

namespace ag::dns {

// The constructor and the destructor are defined in the platform-specific files: on Android
// they need the definition of SystemUpstream::Impl, which only that file has.

std::string SystemUpstream::interface_from_address(std::string_view address) {
    const auto POS = address.find("://");
    return POS != std::string_view::npos ? std::string(address.substr(POS + 3)) : std::string{};
}

ldns_rr *SystemUpstream::create_soa(const ldns_pkt *request) {
    return create_negative_soa(request);
}

} // namespace ag::dns
