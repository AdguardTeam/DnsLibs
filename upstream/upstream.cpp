#include "upstream/upstream.h"
#include "common/logger.h"
#include "common/net_utils.h"
#include "common/route_resolver.h"
#include "common/utils.h"
#include "dnsstamp/dns_stamp.h"
#include "upstream_dnscrypt.h"
#include "upstream_doh.h"
#include "upstream_doq.h"
#include "upstream_dot.h"
#include "upstream_plain.h"
#include <cassert>
#include <chrono>
#include <functional>

namespace ag {

enum class Scheme : size_t {
    SDNS,
    DNS,
    TCP,
    TLS,
    HTTPS,
    QUIC,
    UNDEFINED,
    COUNT,
};

static constexpr std::string_view SCHEME_WITH_SUFFIX[]{"sdns://", "dns://", "tcp://", "tls://", "https://", "quic://"};

static constexpr auto SCHEME_WITH_SUFFIX_BEGIN = std::begin(SCHEME_WITH_SUFFIX);
static constexpr auto SCHEME_WITH_SUFFIX_END = std::end(SCHEME_WITH_SUFFIX);

static_assert(std::size(SCHEME_WITH_SUFFIX) + 1 == static_cast<size_t>(Scheme::COUNT),
        "scheme_with_suffix should contain all schemes defined in enum (except UNDEFINED)");

struct UpstreamFactory::Impl {
    Logger log{"Upstream factory"};
    UpstreamFactoryConfig config;

    Impl(UpstreamFactoryConfig cfg)
            : config(std::move(cfg)) {
    }

    UpstreamFactory::CreateResult create_upstream(const UpstreamOptions &opts) const;
};

static auto get_address_scheme_iterator(std::string_view address) {
    using namespace std::placeholders;
    return std::find_if(
            SCHEME_WITH_SUFFIX_BEGIN, SCHEME_WITH_SUFFIX_END, std::bind(&ag::utils::starts_with, address, _1));
}

static Scheme get_address_scheme(std::string_view address) {
    if (auto i = get_address_scheme_iterator(address); i != SCHEME_WITH_SUFFIX_END) {
        return static_cast<Scheme>(std::distance(SCHEME_WITH_SUFFIX_BEGIN, i));
    }
    return Scheme::UNDEFINED;
}

static UpstreamFactory::CreateResult create_upstream_tls(
        const UpstreamOptions &opts, const UpstreamFactoryConfig &config) {
    return {std::make_unique<DotUpstream>(opts, config), std::nullopt};
}

static UpstreamFactory::CreateResult create_upstream_doq(
        const UpstreamOptions &opts, const UpstreamFactoryConfig &config) {
    return {std::make_unique<DoqUpstream>(opts, config), std::nullopt};
}

static UpstreamFactory::CreateResult create_upstream_https(
        const UpstreamOptions &opts, const UpstreamFactoryConfig &config) {
    return {std::make_unique<DohUpstream>(opts, config), std::nullopt};
}

static UpstreamFactory::CreateResult create_upstream_plain(
        const UpstreamOptions &opts, const UpstreamFactoryConfig &config) {
    return {std::make_unique<PlainUpstream>(opts, config), std::nullopt};
}

static UpstreamFactory::CreateResult create_upstream_dnscrypt(
        ServerStamp &&stamp, const UpstreamOptions &opts, const UpstreamFactoryConfig &config) {
    return {std::make_unique<DnscryptUpstream>(std::move(stamp), opts, config), std::nullopt};
}

static UpstreamFactory::CreateResult create_upstream_dnsquic(
        const UpstreamOptions &opts, const UpstreamFactoryConfig &config) {
    return {std::make_unique<DoqUpstream>(opts, config), std::nullopt};
}

static UpstreamFactory::CreateResult create_upstream_sdns(
        const UpstreamOptions &local_opts, const UpstreamFactoryConfig &config) {
    static constexpr utils::MakeError<UpstreamFactory::CreateResult> make_error;
    auto [stamp, stamp_err] = ServerStamp::from_string(local_opts.address);
    if (stamp_err) {
        return make_error(std::move(stamp_err));
    }
    auto opts = local_opts;
    std::string port; // With leading ':'
    if (!stamp.server_addr_str.empty()) {
        if (stamp.server_addr_str.front() == ':') {
            port = stamp.server_addr_str;
        } else {
            SocketAddress address = ag::utils::str_to_socket_address(stamp.server_addr_str);
            opts.resolved_server_ip = address.addr_variant();
            if (address.port()) {
                port = AG_FMT(":{}", address.port());
            }
        }
    }

    switch (stamp.proto) {
    case StampProtoType::DNSCRYPT:
        return create_upstream_dnscrypt(std::move(stamp), opts, config);
    case StampProtoType::PLAIN:
        opts.address = stamp.server_addr_str;
        return create_upstream_plain(opts, config);
    case StampProtoType::DOH:
        opts.address = AG_FMT("{}{}{}{}", DohUpstream::SCHEME, stamp.provider_name, port, stamp.path);
        return create_upstream_https(opts, config);
    case StampProtoType::TLS:
        opts.address = AG_FMT("{}{}{}", DotUpstream::SCHEME, stamp.provider_name, port);
        return create_upstream_tls(opts, config);
    case StampProtoType::DOQ:
        opts.address = AG_FMT("{}{}{}", DoqUpstream::SCHEME, stamp.provider_name, port);
        return create_upstream_doq(opts, config);
    }
    assert(false);
    return make_error(AG_FMT("Unknown stamp protocol: {}", stamp.proto));
}

UpstreamFactory::CreateResult UpstreamFactory::Impl::create_upstream(const UpstreamOptions &opts) const {
    using CreateFunction = UpstreamFactory::CreateResult (*)(const UpstreamOptions &, const UpstreamFactoryConfig &);
    static constexpr CreateFunction create_functions[]{
            &create_upstream_sdns,
            &create_upstream_plain,
            &create_upstream_plain,
            &create_upstream_tls,
            &create_upstream_https,
            &create_upstream_dnsquic,
            &create_upstream_plain,
    };
    static_assert(std::size(create_functions) == static_cast<size_t>(Scheme::COUNT),
            "create_functions should contains all create functions for schemes defined in enum");
    auto index = (size_t) get_address_scheme(opts.address);
    return create_functions[index](opts, this->config);
}

UpstreamFactory::UpstreamFactory(UpstreamFactoryConfig cfg)
        : m_factory(std::make_unique<Impl>(std::move(cfg))) {
}

UpstreamFactory::~UpstreamFactory() = default;

UpstreamFactory::CreateResult UpstreamFactory::create_upstream(const UpstreamOptions &opts) const {
    CreateResult result;
    if (opts.address.find("://") != std::string_view::npos) {
        result = m_factory->create_upstream(opts);
    } else {
        // We don't have scheme in the url, so it's just a plain DNS host:port
        result = create_upstream_plain(opts, m_factory->config);
    }

    if (!result.error.has_value()) {
        result.error = result.upstream->init();
    }

    if (result.error.has_value()) {
        result.upstream.reset();
    }

    return result;
}

} // namespace ag
