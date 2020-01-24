#include <cassert>
#include <functional>
#include <upstream.h>
#include "upstream_dnscrypt.h"
#include "upstream_doh.h"
#include "upstream_dot.h"
#include "upstream_plain.h"
#include <ag_utils.h>
#include <ag_logger.h>
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


struct ag::upstream_factory::impl {
    logger log = create_logger("Upstream factory");
    upstream_factory_config config;

    impl(upstream_factory_config cfg)
        : config(std::move(cfg))
    {}

    upstream_factory::create_result create_upstream(const upstream::options &opts) const;
};


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

static ag::upstream_factory::create_result create_upstream_tls(const ag::upstream::options &opts,
        const ag::upstream_factory_config &config) {
    return {std::make_unique<ag::dns_over_tls>(opts, config), std::nullopt};
}

static ag::upstream_factory::create_result create_upstream_https(const ag::upstream::options &opts,
        const ag::upstream_factory_config &config) {
    return {std::make_unique<ag::dns_over_https>(opts, config), std::nullopt};
}

static ag::upstream_factory::create_result create_upstream_plain(const ag::upstream::options &opts,
        const ag::upstream_factory_config &config) {
    return {std::make_unique<ag::plain_dns>(opts, config), std::nullopt};
}

static ag::upstream_factory::create_result create_upstream_dnscrypt(ag::server_stamp &&stamp,
        const ag::upstream::options &opts) {
    return {std::make_unique<ag::upstream_dnscrypt>(std::move(stamp), opts.timeout), std::nullopt};
}

static ag::upstream_factory::create_result create_upstream_sdns(const ag::upstream::options &local_opts,
        const ag::upstream_factory_config &config) {
    static constexpr ag::utils::make_error<ag::upstream_factory::create_result> make_error;
    auto[stamp, stamp_err] = ag::server_stamp::from_string(local_opts.address);
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
        opts.resolved_server_ip = ip_address_variant;
    }
    opts.address = stamp.server_addr_str;

    switch (stamp.proto) {
    case ag::stamp_proto_type::PLAIN:
        return create_upstream_plain(opts, config);
    case ag::stamp_proto_type::DNSCRYPT:
        return create_upstream_dnscrypt(std::move(stamp), opts);
    case ag::stamp_proto_type::DOH:
        opts.address = AG_FMT("{}{}{}", ag::dns_over_https::SCHEME, stamp.provider_name, stamp.path);
        return create_upstream_https(opts, config);
    case ag::stamp_proto_type::TLS:
        opts.address = AG_FMT("{}{}", ag::dns_over_tls::SCHEME, stamp.provider_name);
        return create_upstream_tls(opts, config);
    }
    assert(false);
    return make_error(AG_FMT("Unknown stamp protocol: {}", stamp.proto));
}

ag::upstream_factory::create_result ag::upstream_factory::impl::create_upstream(const ag::upstream::options &opts) const {
    using create_function = upstream_factory::create_result (*)(const ag::upstream::options &, const ag::upstream_factory_config &);
    static constexpr create_function create_functions[]{
        &create_upstream_sdns,
        &create_upstream_plain,
        &create_upstream_plain,
        &create_upstream_tls,
        &create_upstream_https,
        &create_upstream_plain,
    };
    static_assert(std::size(create_functions) == static_cast<size_t>(scheme::COUNT),
                  "create_functions should contains all create functions for schemes defined in enum");
    auto index = (size_t)get_address_scheme(opts.address);
    return create_functions[index](opts, this->config);
}

ag::upstream_factory::upstream_factory(upstream_factory_config cfg)
    : factory(std::make_unique<impl>(std::move(cfg)))
{}

ag::upstream_factory::~upstream_factory() = default;

ag::upstream_factory::create_result ag::upstream_factory::create_upstream(const upstream::options &opts) const {
    create_result result;
    if (opts.address.find("://") != std::string_view::npos) {
        // TODO parse address error
        result = this->factory->create_upstream(opts);
    } else {
        // We don't have scheme in the url, so it's just a plain DNS host:port
        result = create_upstream_plain(opts, this->factory->config);
    }

    if (!result.error.has_value()) {
        result.error = result.upstream->init();
    }

    if (result.error.has_value()) {
        result.upstream.reset();
    }

    return result;
}
