#include <upstream.h>
#include <ag_utils.h>
#include <dns_stamp.h>
#include "upstream_plain.h"
#include "upstream_dot.h"
#include "upstream_dnscrypt.h"

ag::upstream::address_to_upstream_result ag::upstream::address_to_upstream(std::string_view address, const ag::upstream::options &opts) {
    bool prefer_tcp = false;
    if (auto[stamp, stamp_err] = server_stamp::from_string(address); !stamp_err && stamp.proto == stamp_proto_type::DNSCRYPT) {
        return {std::make_shared<upstream_dnscrypt>(std::move(stamp), opts.timeout), std::nullopt};
    } else if (address.find("://") != std::string_view::npos) {
        // TODO: URLs support
        if (utils::starts_with(address, "tcp://")) {
            address.remove_prefix(6);
            prefer_tcp = true;
        } else if (utils::starts_with(address, "tls://")) {
            address.remove_prefix(6);
            bootstrapper_ptr bootstrapper = std::make_shared<ag::bootstrapper>(address, dns_over_tls::DEFAULT_PORT, true, opts.bootstrap);
            return {std::make_shared<dns_over_tls>(bootstrapper, opts.timeout), std::nullopt};
        }
    }
    // we don't have scheme in the url, so it's just a plain DNS host:port
    auto port = utils::split_host_port(address).second;
    std::string addr_str;
    if (port.empty()) {
        // doesn't have port, default to 53
        addr_str = utils::join_host_port(address, "53");
        address = addr_str;
    }
    return {std::make_shared<plain_dns>(address, opts.timeout, prefer_tcp), std::nullopt};
}
