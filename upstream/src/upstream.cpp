#include <cassert>
#include <functional>
#include <upstream.h>
#include "upstream_dnscrypt.h"
#include "upstream_doh.h"
#include "upstream_dot.h"
#include "upstream_plain.h"
#include <ag_utils.h>
#include <dns_stamp.h>

enum class scheme : size_t {
    SDNS,
    DNS,
    TCP,
    TLS,
    HTTPS,
    UNDEFINED,
    COUNT,
};

static constexpr std::string_view SCHEME_WITH_SUFFIX[]{
    "sdns://",
    "dns://",
    "tcp://",
    "tls://",
    "https://",
};

static constexpr auto SCHEME_WITH_SUFFIX_BEGIN = std::begin(SCHEME_WITH_SUFFIX);
static constexpr auto SCHEME_WITH_SUFFIX_END = std::end(SCHEME_WITH_SUFFIX);

static_assert(std::size(SCHEME_WITH_SUFFIX) + 1 == static_cast<size_t>(scheme::COUNT),
              "scheme_with_suffix should contain all schemes defined in enum (except UNDEFINED)");

static auto get_address_scheme_iterator(std::string_view address) {
    using namespace std::placeholders;
    return std::find_if(SCHEME_WITH_SUFFIX_BEGIN, SCHEME_WITH_SUFFIX_END,
                        std::bind(&ag::utils::starts_with, address, _1));
}

static scheme get_address_scheme(std::string_view address) {
    if (auto i = get_address_scheme_iterator(address); i != SCHEME_WITH_SUFFIX_END) {
        return static_cast<scheme>(std::distance(SCHEME_WITH_SUFFIX_BEGIN, i));
    }
    return scheme::UNDEFINED;
}

static constexpr std::string_view get_address_scheme_with_suffix(scheme local_scheme) {
    if (local_scheme == scheme::UNDEFINED) {
        return "";
    }
    return SCHEME_WITH_SUFFIX[static_cast<size_t>(local_scheme)];
}

static constexpr size_t get_address_scheme_size(scheme local_scheme) {
    return std::size(get_address_scheme_with_suffix(local_scheme));
}

static ag::upstream::address_to_upstream_result create_upstream_tls_without_prefix(std::string_view address,
                                                                                   const ag::upstream::options &opts) {
    auto bootstrapper = std::make_shared<ag::bootstrapper>(address, ag::dns_over_tls::DEFAULT_PORT, true,
                                                           opts.bootstrap);
    return {std::make_shared<ag::dns_over_tls>(std::move(bootstrapper), opts.timeout), std::nullopt};
}

static ag::upstream::address_to_upstream_result create_upstream_tls(std::string_view address,
                                                                    const ag::upstream::options &opts) {
    address.remove_prefix(get_address_scheme_size(scheme::TLS));
    return create_upstream_tls_without_prefix(address, opts);
}

static ag::upstream::address_to_upstream_result create_upstream_https(std::string_view address,
                                                                      const ag::upstream::options &opts) {
    return {std::make_shared<ag::dns_over_https>(address, opts), std::nullopt};
}

static ag::upstream::address_to_upstream_result create_upstream_https_without_prefix(
        std::string_view address, const ag::upstream::options &opts) {
    return create_upstream_https(AG_FMT("{}{}", ag::dns_over_https::SCHEME, address), opts);
}

static ag::upstream::address_to_upstream_result create_upstream_dns_common(std::string_view address,
                                                                           const ag::upstream::options &opts,
                                                                           bool prefer_tcp) {
    return {std::make_shared<ag::plain_dns>(address, opts.timeout, prefer_tcp), std::nullopt};
}

static ag::upstream::address_to_upstream_result create_upstream_dns(std::string_view address,
                                                                    const ag::upstream::options &opts) {
    return create_upstream_dns_common(address, opts, false);
}

static ag::upstream::address_to_upstream_result create_upstream_tcp(std::string_view address,
                                                                    const ag::upstream::options &opts) {
    address.remove_prefix(get_address_scheme_size(scheme::TCP));
    return create_upstream_dns_common(address, opts, true);
}

static ag::upstream::address_to_upstream_result create_upstream_dnscrypt(ag::server_stamp &&stamp,
                                                                         const ag::upstream::options &opts) {
    return {std::make_shared<ag::upstream_dnscrypt>(std::move(stamp), opts.timeout), std::nullopt};
}

static ag::upstream::address_to_upstream_result create_upstream_sdns(std::string_view stamp_address,
                                                                     const ag::upstream::options &local_opts) {
    static constexpr ag::utils::make_error<ag::upstream::address_to_upstream_result> make_error;
    auto[stamp, stamp_err] = ag::server_stamp::from_string(stamp_address);
    if (stamp_err) {
        return make_error(std::move(stamp_err));
    }
    auto opts = local_opts;
    if (!stamp.server_addr_str.empty()) {
        auto host = ag::utils::split_host_port(stamp.server_addr_str).first;
        auto ip_address_variant = ag::socket_address(host).addr_variant();
        if (std::holds_alternative<std::monostate>(ip_address_variant)) {
            return make_error(AG_FMT("Invalid server address in the stamp: {}", stamp.server_addr_str));
        }
        opts.server_ip = ip_address_variant;
    }
    switch (stamp.proto) {
    case ag::stamp_proto_type::PLAIN:
        return create_upstream_dns(stamp.server_addr_str, opts);
    case ag::stamp_proto_type::DNSCRYPT:
        return create_upstream_dnscrypt(std::move(stamp), opts);
    case ag::stamp_proto_type::DOH:
        return create_upstream_https_without_prefix(AG_FMT("{}{}", stamp.provider_name, stamp.path), opts);
    case ag::stamp_proto_type::TLS:
        return create_upstream_tls_without_prefix(stamp.provider_name, opts);
    }
    assert(false);
    return make_error(AG_FMT("Unknown stamp protocol: {}", stamp.proto));
}

static ag::upstream::address_to_upstream_result create_upstream_common(std::string_view address,
                                                                       const ag::upstream::options &opts) {
    using create_function = decltype(&create_upstream_common);
    static constexpr create_function create_functions[]{
        &create_upstream_sdns,
        &create_upstream_dns,
        &create_upstream_tcp,
        &create_upstream_tls,
        &create_upstream_https,
        &create_upstream_dns,
    };
    static_assert(std::size(create_functions) == static_cast<size_t>(scheme::COUNT),
                  "create_functions should contains all create functions for schemes defined in enum");
    auto index = (size_t)get_address_scheme(address);
    return create_functions[index](address, opts);
}

ag::upstream::address_to_upstream_result ag::upstream::address_to_upstream(std::string_view address,
                                                                           const options &opts) {
    if (address.find("://") != std::string_view::npos) {
        // TODO parse address error
        return create_upstream_common(address, opts);
    }
    // We don't have scheme in the url, so it's just a plain DNS host:port
    return create_upstream_dns(address, opts);
}
