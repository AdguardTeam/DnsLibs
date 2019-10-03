#include <upstream.h>
#include "upstream_plain.h"

std::pair<ag::upstream_ptr, ag::err_string> ag::upstream::address_to_upstream(std::string_view address, ag::upstream::options &opts) {
    bool prefer_tcp = false;
    if (address.find("://") != std::string_view::npos) {
        // TODO: URLs support
        if (address.substr(0, 6) == "tcp://") {
            address = address.substr(6);
            prefer_tcp = true;
        }
    }

    // we don't have scheme in the url, so it's just a plain DNS host:port
    auto port = std::get<1>(ag::util::split_host_port(address));
    std::string addr_str;
    if (port.empty()) {
        // doesn't have port, default to 53
        addr_str = ag::util::join_host_port(address, "53");
        address = addr_str;
    }
    return {std::make_shared<ag::plain_dns>(address, opts.timeout, prefer_tcp), std::nullopt};
}
