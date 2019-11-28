#include <functional>
#include <upstream.h>
#include "upstream_dnscrypt.h"
#include "upstream_doh.h"
#include "upstream_dot.h"
#include "upstream_plain.h"
#include <ag_utils.h>
#include <dns_stamp.h>

enum class scheme {
    SDNS,
    DNS,
    TCP,
    TLS,
    HTTPS,
    UNDEFINED,
    COUNT = UNDEFINED + 1,
};

static scheme get_address_scheme(std::string_view address) {
    using namespace std::placeholders;
    static const std::string_view scheme_with_suffix[]{
        "sdns://",
        "dns://",
        "tcp://",
        "tls://",
        "https://",
    };
    static_assert(std::size(scheme_with_suffix) + 1 == static_cast<size_t>(scheme::COUNT),
                  "scheme_with_suffix should contain all schemes defined in enum (except UNDEFINED)");
    static constexpr auto scheme_with_suffix_end = std::end(scheme_with_suffix);
    auto i = std::find_if(std::begin(scheme_with_suffix), scheme_with_suffix_end,
                          std::bind(&ag::utils::starts_with, address, _1));
    if (i != scheme_with_suffix_end) {
        return static_cast<scheme>(std::distance(i, scheme_with_suffix_end));
    }
    return scheme::UNDEFINED;
}

#if 0 // TODO remove?
static std::string get_host_with_port(std::string_view address, std::string_view default_port) {
    if (ag::utils::split_host_port(address).second.empty()) {
        return ag::utils::join_host_port(address, default_port);
    }
    return std::string(address);
}
#endif

ag::upstream::address_to_upstream_result ag::upstream::address_to_upstream(std::string_view address, const options &opts) {
    if (address.find("://") != std::string_view::npos) {
        // TODO parse address error
        return url_to_upstream(address, opts);
    }
    // We don't have scheme in the url, so it's just a plain DNS host:port
    return {std::make_shared<plain_dns>(address, opts.timeout, false), std::nullopt};
}

ag::upstream::address_to_upstream_result ag::upstream::url_to_upstream(std::string_view address, const options &opts) {
    bool prefer_tcp = false;
    switch (get_address_scheme(address)) {
    case scheme::SDNS:
        return stamp_to_upstream(address, opts);
    case scheme::TLS: {
        address.remove_prefix(6);
        auto bootstrapper = std::make_shared<ag::bootstrapper>(address, dns_over_tls::DEFAULT_PORT, true,
                                                               opts.bootstrap);
        return {std::make_shared<dns_over_tls>(bootstrapper, opts.timeout), std::nullopt};
    }
    case scheme::HTTPS:
        return {std::make_shared<dns_over_https>(address, opts), std::nullopt};
    case scheme::TCP:
        prefer_tcp = true;
        address.remove_prefix(6);
        [[fallthrough]];
    case scheme::DNS:
    default:
        return {std::make_shared<plain_dns>(address, opts.timeout, prefer_tcp), std::nullopt};
    }
}

ag::upstream::address_to_upstream_result ag::upstream::stamp_to_upstream(std::string_view stamp_address, options opts) {
    static constexpr utils::make_error<address_to_upstream_result> make_error;
    auto[stamp, stamp_err] = server_stamp::from_string(stamp_address);
    if (stamp_err) {
        return make_error(std::move(stamp_err));
    }
    if (!stamp.server_addr_str.empty()) {
        auto host = utils::split_host_port(stamp.server_addr_str).first;
        auto ip_address_variant = socket_address(host).addr_variant();
        if (std::holds_alternative<std::monostate>(ip_address_variant)) {
            return make_error("Invalid server address in the stamp: " + std::move(stamp.server_addr_str));
        }
        opts.server_ip = ip_address_variant;
    }
    switch (stamp.proto) {
    case stamp_proto_type::PLAIN:
        return {std::make_shared<plain_dns>(stamp.server_addr_str, opts.timeout, false), std::nullopt};
    case stamp_proto_type::DNSCRYPT:
        return {std::make_shared<upstream_dnscrypt>(std::move(stamp), opts.timeout), std::nullopt};
    case stamp_proto_type::DOH:
        // TODO remove recursion?
        return address_to_upstream("https://" + stamp.provider_name + stamp.path, opts); // TODO scheme
    case stamp_proto_type::TLS:
        // TODO remove recursion?
        return address_to_upstream("tls://" + stamp.provider_name, opts); // TODO scheme
    }
}
