#include <upstream.h>
#include <ag_utils.h>
#include "upstream_plain.h"
#include "upstream_dot.h"

std::pair<ag::upstream_ptr, ag::err_string> ag::upstream::address_to_upstream(std::string_view address, const ag::upstream::options &opts) {
    bool prefer_tcp = false;
    if (address.find("://") != std::string_view::npos) {
        // TODO: URLs support
        if (ag::utils::starts_with(address, "tcp://")) {
            address.remove_prefix(6);
            prefer_tcp = true;
        } else if (ag::utils::starts_with(address, "tls://")) {
            address.remove_prefix(6);
            bootstrapper_ptr bootstrapper = std::make_shared<ag::bootstrapper>(address, ag::dns_over_tls::DEFAULT_PORT, true, opts.bootstrap);
            return {std::make_shared<ag::dns_over_tls>(bootstrapper, opts.timeout), std::nullopt};
        }
    }

    // we don't have scheme in the url, so it's just a plain DNS host:port
    auto port = ag::util::split_host_port(address).second;
    std::string addr_str;
    if (port.empty()) {
        // doesn't have port, default to 53
        addr_str = ag::util::join_host_port(address, "53");
        address = addr_str;
    }
    return {std::make_shared<ag::plain_dns>(address, opts.timeout, prefer_tcp), std::nullopt};
}
