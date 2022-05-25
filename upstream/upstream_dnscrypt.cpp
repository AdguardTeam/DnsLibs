#include "upstream_dnscrypt.h"
#include "common/clock.h"
#include "common/logger.h"
#include "common/utils.h"
#include "dnscrypt/dns_crypt_client.h"
#include <chrono>
#include <memory>
#include <sodium.h>

#define tracelog_id(log_, pkt_, fmt_, ...) tracelog(log_, "[{}] " fmt_, ldns_pkt_id(pkt_), ##__VA_ARGS__)

using std::chrono::duration_cast;

namespace ag {

static Logger logger{"UPSTREAM DNSCRYPT"};

struct SodiumInitializer {
    SodiumInitializer() {
        if (sodium_init() == -1) {
            errlog(logger, "Failed to initialize libsodium");
        }
    }
};

struct DnscryptUpstream::Impl {
    dnscrypt::Client udp_client;
    dnscrypt::ServerInfo server_info;
};

static UpstreamOptions make_dnscrypt_options(const ServerStamp &stamp, const UpstreamOptions &opts) {
    UpstreamOptions converted = opts;
    converted.address = stamp.server_addr_str;
    return converted;
}

DnscryptUpstream::DnscryptUpstream(
        ServerStamp &&stamp, const UpstreamOptions &opts, const UpstreamFactoryConfig &config)
        : Upstream(make_dnscrypt_options(stamp, opts), config)
        , m_log("DNScrypt upstream")
        , m_stamp(std::move(stamp)) {
    static const SodiumInitializer ensure_initialized;
}

ErrString DnscryptUpstream::init() {
    return std::nullopt;
}

DnscryptUpstream::~DnscryptUpstream() = default;

DnscryptUpstream::ExchangeResult DnscryptUpstream::exchange(ldns_pkt *request_pkt, const DnsMessageInfo *) {
    tracelog_id(m_log, request_pkt, "Started");
    static constexpr utils::MakeError<ExchangeResult> make_error;
    SetupResult result = setup_impl();
    if (result.error.has_value()) {
        return make_error(std::move(result.error));
    }
    if (m_options.timeout < result.rtt) {
        return make_error(AG_FMT("Certificate fetch took too much time: {}ms", result.rtt.count()));
    }
    auto [reply, reply_err] = apply_exchange(*request_pkt, m_options.timeout - result.rtt);
    if (reply_err) {
        return make_error(std::move(reply_err));
    }
    if (reply && ldns_pkt_id(reply.get()) != ldns_pkt_id(request_pkt)) {
        return make_error("Request and reply ids are not equal");
    }
    tracelog_id(m_log, request_pkt, "Finished");
    return {std::move(reply), std::nullopt};
}

DnscryptUpstream::SetupResult DnscryptUpstream::setup_impl() {
    Millis rtt(0);
    auto now = duration_cast<Millis>(SteadyClock::now().time_since_epoch()).count();
    if (std::scoped_lock l(m_guard); !m_impl || m_impl->server_info.get_server_cert().not_after < now) {
        ag::dnscrypt::Client client;
        auto [dial_server_info, dial_rtt, dial_err]
                = client.dial(m_stamp, m_options.timeout, m_config.socket_factory, this->make_socket_parameters());
        if (dial_err) {
            return {rtt,
                    AG_FMT("Failed to fetch certificate info from {} with error: {}", m_options.address, *dial_err)};
        }
        m_impl = std::make_unique<Impl>(Impl{client, std::move(dial_server_info)});
        rtt = dial_rtt;
    }
    return {rtt};
}

DnscryptUpstream::ExchangeResult DnscryptUpstream::apply_exchange(ldns_pkt &request_pkt, Millis timeout) {
    Impl local_upstream;
    {
        std::scoped_lock l(m_guard);
        local_upstream = *m_impl;
    }

    utils::Timer timer;

    auto [udp_reply, udp_reply_rtt, udp_reply_err] = local_upstream.udp_client.exchange(
            request_pkt, local_upstream.server_info, timeout, m_config.socket_factory, this->make_socket_parameters());

    if (udp_reply && ldns_pkt_tc(udp_reply.get())) {
        tracelog_id(m_log, &request_pkt, "Truncated message was received, retrying over TCP");
        dnscrypt::Client tcp_client(utils::TP_TCP);

        timeout -= timer.elapsed<decltype(timeout)>();
        if (timeout <= decltype(timeout)(0)) {
            return {nullptr, evutil_socket_error_to_string(utils::AG_ETIMEDOUT)};
        }

        auto [tcp_reply, tcp_reply_rtt, tcp_reply_err] = tcp_client.exchange(request_pkt, local_upstream.server_info,
                timeout, m_config.socket_factory, this->make_socket_parameters());
        return {std::move(tcp_reply), std::move(tcp_reply_err)};
    }
    return {std::move(udp_reply), std::move(udp_reply_err)};
}

SocketFactory::SocketParameters DnscryptUpstream::make_socket_parameters() const {
    SocketFactory::SocketParameters socket_parameters = {};
    socket_parameters.outbound_interface = m_options.outbound_interface;
    socket_parameters.ignore_proxy_settings = m_options.ignore_proxy_settings;
    return socket_parameters;
}

} // namespace ag
