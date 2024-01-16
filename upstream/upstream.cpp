#include <cassert>
#include <chrono>
#include <functional>

#include <ada.h>
#include <magic_enum/magic_enum.hpp>

#include "common/base64.h"
#include "common/logger.h"
#include "common/net_utils.h"
#include "common/route_resolver.h"
#include "common/utils.h"
#include "dns/dnsstamp/dns_stamp.h"
#include "dns/upstream/upstream.h"
#include "upstream_dnscrypt.h"
#include "upstream_doh.h"
#include "upstream_doq.h"
#include "upstream_dot.h"
#include "upstream_plain.h"
#ifdef __APPLE__
#include "upstream_system.h"
#endif //_APPLE

namespace ag::dns {

enum class Scheme : size_t {
    SDNS,
    DNS,
    TCP,
    UDP,
    TLS,
    HTTPS,
    H3,
    QUIC,
    SYSTEM,
    UNDEFINED,
};

static constexpr std::string_view SCHEME_WITH_SUFFIX[] = {
        "sdns://",
        "dns://",
        PlainUpstream::TCP_SCHEME,
        PlainUpstream::UDP_SCHEME,
        DotUpstream::SCHEME,
        DohUpstream::SCHEME_HTTPS,
        DohUpstream::SCHEME_H3,
        DoqUpstream::SCHEME,
        "system://",
};

static_assert(std::size(SCHEME_WITH_SUFFIX) + 1 == magic_enum::enum_count<Scheme>(),
        "scheme_with_suffix should contain all schemes defined in enum (except UNDEFINED)");

struct UpstreamFactory::Impl {
    Logger log{"Upstream factory"};
    UpstreamFactoryConfig config;

    Impl(UpstreamFactoryConfig cfg)
            : config(std::move(cfg)) {
        if (config.timeout.count() == 0) {
            config.timeout = DEFAULT_TIMEOUT;
        }
    }
    UpstreamFactory::CreateResult create_upstream(const UpstreamOptions &opts) const;
};

static auto get_address_scheme_iterator(std::string_view address) {
    using namespace std::placeholders;
    return std::find_if(std::begin(SCHEME_WITH_SUFFIX), std::end(SCHEME_WITH_SUFFIX), [&](auto scheme) {
        return utils::istarts_with(address, scheme);
    });
}

static Scheme get_address_scheme(std::string_view address) {
    if (auto i = get_address_scheme_iterator(address); i != std::end(SCHEME_WITH_SUFFIX)) {
        return static_cast<Scheme>(std::distance(std::begin(SCHEME_WITH_SUFFIX), i));
    }
    return Scheme::UNDEFINED;
}

static Result<std::vector<CertFingerprint>, UpstreamFactory::UpstreamCreateError> parse_fingerprints(
        const UpstreamOptions &opts) {
    std::vector<CertFingerprint> result;
    result.reserve(opts.fingerprints.size());
    for (auto &fp : opts.fingerprints) {
        auto fingerprint_decoded = decode_base64(fp, false);
        if (fingerprint_decoded.has_value()) {
            SpkiSha256Digest &spki = result.emplace_back().emplace<SpkiSha256Digest>();
            std::copy_n(fingerprint_decoded.value().begin(), fingerprint_decoded.value().size(), spki.data.begin());
        } else {
            return make_error(UpstreamFactory::UpstreamCreateError::AE_INVALID_FINGERPRINT,
                    AG_FMT("Invalid fingerprint: {}", fp));
        }
    }
    return result;
}

using CreateResult = UpstreamFactory::CreateResult;

static CreateResult create_upstream_system(
        const UpstreamOptions &opts, const UpstreamFactoryConfig &config, std::vector<CertFingerprint>/*fingerprints*/ ) {
#ifdef __APPLE__
    return CreateResult{std::make_unique<SystemUpstream>(opts, config)};
#else
    return make_error(UpstreamFactory::UpstreamCreateError::AE_NOT_SUPPORTED, "");
#endif
}

static CreateResult create_upstream_tls(
        const UpstreamOptions &opts, const UpstreamFactoryConfig &config, std::vector<CertFingerprint> fingerprints) {
    return CreateResult{std::make_unique<DotUpstream>(opts, config, std::move(fingerprints))};
}

static CreateResult create_upstream_doq(
        const UpstreamOptions &opts, const UpstreamFactoryConfig &config, std::vector<CertFingerprint> fingerprints) {
    return CreateResult{std::make_unique<DoqUpstream>(opts, config, std::move(fingerprints))};
}

static UpstreamFactory::CreateResult create_upstream_https(
        const UpstreamOptions &opts, const UpstreamFactoryConfig &config, std::vector<CertFingerprint> fingerprints) {
    return CreateResult{std::make_unique<DohUpstream>(opts, config, std::move(fingerprints))};
}

static CreateResult create_upstream_plain(
        const UpstreamOptions &opts, const UpstreamFactoryConfig &config, std::vector<CertFingerprint>) {
    return CreateResult{std::make_unique<PlainUpstream>(opts, config)};
}

static CreateResult create_upstream_dnscrypt(ServerStamp &&stamp, const UpstreamOptions &opts,
        const UpstreamFactoryConfig &config, std::vector<CertFingerprint>) {
    return CreateResult{std::make_unique<DnscryptUpstream>(std::move(stamp), opts, config)};
}

static CreateResult create_upstream_sdns(const UpstreamOptions &local_opts, const UpstreamFactoryConfig &config,
        std::vector<CertFingerprint> fingerprints) {
    auto stamp_res = ServerStamp::from_string(local_opts.address);
    if (stamp_res.has_error()) {
        return CreateResult{make_error(UpstreamFactory::UpstreamCreateError::AE_INVALID_STAMP, stamp_res.error())};
    }
    auto &stamp = stamp_res.value();
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

    for (auto &hash : stamp.hashes) {
        TbsCertSha256Digest &cert_digest = fingerprints.emplace_back().emplace<TbsCertSha256Digest>();
        std::copy_n(hash.begin(), SHA256_DIGEST_LENGTH, cert_digest.data.begin());
    }

    std::string_view creds;
    switch (stamp.proto) {
    case StampProtoType::DNSCRYPT:
        return create_upstream_dnscrypt(std::move(stamp), opts, config, std::move(fingerprints));
    case StampProtoType::PLAIN:
        opts.address = stamp.server_addr_str;
        return create_upstream_plain(opts, config, std::move(fingerprints));
    case StampProtoType::DOH:
        if (auto pos = opts.address.find('@'); pos != std::string::npos) {
            creds = opts.address;
            creds.remove_suffix(creds.size() - pos - 1);
            creds.remove_prefix(SCHEME_WITH_SUFFIX[(int) Scheme::SDNS].size());
        }
        opts.address = AG_FMT("{}{}{}{}{}", DohUpstream::SCHEME_HTTPS, creds, stamp.provider_name, port, stamp.path);
        return create_upstream_https(opts, config, std::move(fingerprints));
    case StampProtoType::TLS:
        opts.address = AG_FMT("{}{}{}", DotUpstream::SCHEME, stamp.provider_name, port);
        return create_upstream_tls(opts, config, std::move(fingerprints));
    case StampProtoType::DOQ:
        opts.address = AG_FMT("{}{}{}", DoqUpstream::SCHEME, stamp.provider_name, port);
        return create_upstream_doq(opts, config, std::move(fingerprints));
    }
    assert(false);
    return make_error(UpstreamFactory::UpstreamCreateError::AE_INVALID_STAMP,
            AG_FMT("Unknown stamp protocol: {}", magic_enum::enum_name(stamp.proto)));
}

UpstreamFactory::CreateResult UpstreamFactory::Impl::create_upstream(const UpstreamOptions &opts) const {
    using CreateFunction = UpstreamFactory::CreateResult (*)(
            const UpstreamOptions &, const UpstreamFactoryConfig &, std::vector<CertFingerprint>);
    static constexpr CreateFunction create_functions[]{
            &create_upstream_sdns,
            &create_upstream_plain,
            &create_upstream_plain,
            &create_upstream_plain,
            &create_upstream_tls,
            &create_upstream_https,
            &create_upstream_https,
            &create_upstream_doq,
            &create_upstream_system,
            &create_upstream_plain, // Undefined
    };
    static_assert(std::size(create_functions) == magic_enum::enum_count<Scheme>(),
            "create_functions should contains all create functions for schemes defined in enum");
    auto index = (size_t) get_address_scheme(opts.address);
    auto fingerprints = parse_fingerprints(opts);
    if (fingerprints.has_error()) {
        return fingerprints.error();
    }
    return create_functions[index](opts, this->config, std::move(fingerprints.value()));
}

UpstreamFactory::UpstreamFactory(UpstreamFactoryConfig cfg)
        : m_factory(std::make_unique<Impl>(std::move(cfg))) {
}

UpstreamFactory::~UpstreamFactory() = default;

UpstreamFactory::CreateResult UpstreamFactory::create_upstream(const UpstreamOptions &opts) const {
    bool have_scheme = (opts.address.find("://") != std::string_view::npos);
    CreateResult result = have_scheme ? m_factory->create_upstream(opts)
                                      : create_upstream_plain(opts, m_factory->config, std::vector<CertFingerprint>());
    if (result.has_value()) {
        auto init_err = result.value()->init();
        if (init_err) {
            return make_error(UpstreamFactory::UpstreamCreateError::AE_INIT_FAILED, init_err);
        }
    }
    return result;
}

Error<Upstream::InitError> Upstream::init_url_port(bool allow_creds, bool allow_path, uint16_t default_port, bool host_to_lowercase) {
    auto url = ada::parse<ada::url_aggregator>(m_options.address, nullptr);
    if (!url) {
        return make_error(InitError::AE_INVALID_ADDRESS, "Invalid URL");
    }
    if (url->get_hostname().empty()) {
        return make_error(InitError::AE_INVALID_ADDRESS, "Host cannot be empty");
    }
    if (allow_creds && url->get_username().empty() != url->get_password().empty()) {
        return make_error(InitError::AE_INVALID_ADDRESS, "Both username and password should be specified");
    }
    if (!allow_creds && (!url->get_username().empty() || !url->get_password().empty())) {
        return make_error(InitError::AE_INVALID_ADDRESS, "Unexpected credentials");
    }
    if (!allow_path && !url->get_pathname().empty() && url->get_pathname() != "/") {
        return make_error(InitError::AE_INVALID_ADDRESS, "Unexpected path");
    }
    if (!url->is_special()) {
        if (allow_path && url->get_pathname().empty()) {
            url->set_pathname("/");
        }
    }
    if (host_to_lowercase) {
        url->set_host(utils::to_lower(url->get_host()));
    }
    uint16_t port = url->get_port().empty()
            ? default_port
            : ag::utils::to_integer<uint16_t>(url->get_port()).value(); // NOLINT(*-unchecked-optional-access)
    m_url = std::move(url.value());
    m_port = port;
    return {};
}

} // namespace ag::dns
