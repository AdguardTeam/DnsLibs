#include "upstream_dnscrypt.h"
#include "common/clock.h"
#include "common/logger.h"
#include "common/utils.h"
#include "dns/dnscrypt/dns_crypt_client.h"
#include <chrono>
#include <memory>
#include <sodium.h>

#define tracelog_id(log_, pkt_, fmt_, ...) tracelog(log_, "[{}] " fmt_, ldns_pkt_id(pkt_), ##__VA_ARGS__)

using std::chrono::duration_cast;

namespace ag::dns {

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
        , m_stamp(std::move(stamp))
        , m_shutdown_guard(std::make_shared<bool>(true)) {
    static const SodiumInitializer ensure_initialized;
}

Error<Upstream::InitError> DnscryptUpstream::init() {
    return {};
}

DnscryptUpstream::~DnscryptUpstream() = default;

coro::Task<Upstream::ExchangeResult> DnscryptUpstream::exchange(const ldns_pkt *request_pkt, const DnsMessageInfo *) {
    tracelog_id(m_log, request_pkt, "Started");
    std::weak_ptr<bool> guard = m_shutdown_guard;

    SetupResult result = co_await setup_impl();
    if (guard.expired()) {
        co_return make_error(DnsError::AE_SHUTTING_DOWN);
    }
    if (result.error) {
        co_return result.error;
    }
    if (m_config.timeout < result.rtt) {
        co_return make_error(DnsError::AE_TIMED_OUT, AG_FMT("Certificate fetch took too much time: {}ms", result.rtt.count()));
    }
    auto reply = co_await apply_exchange(*request_pkt, m_config.timeout - result.rtt);
    if (guard.expired()) {
        co_return make_error(DnsError::AE_SHUTTING_DOWN);
    }
    if (reply.has_error()) {
        co_return reply.error();
    }
    if (reply && ldns_pkt_id(reply->get()) != ldns_pkt_id(request_pkt)) {
        co_return make_error(DnsError::AE_REPLY_PACKET_ID_MISMATCH);
    }
    tracelog_id(m_log, request_pkt, "Finished");
    co_return std::move(reply.value());
}

coro::Task<DnscryptUpstream::SetupResult> DnscryptUpstream::setup_impl() {
    Millis rtt(0);
    auto now = duration_cast<Millis>(SteadyClock::now().time_since_epoch()).count();
    if (!m_impl || m_impl->server_info.get_server_cert().not_after < now) {
        dnscrypt::Client client;
        auto dial_res
                = co_await client.dial(m_stamp, this->config().loop, m_config.timeout, m_config.socket_factory, this->make_socket_parameters());
        if (dial_res.has_error()) {
            co_return {rtt, make_error(DnsError::AE_HANDSHAKE_ERROR,
                    AG_FMT("Failed to fetch certificate info from {}", m_options.address), dial_res.error())};
        }
        auto &[dial_server_info, dial_rtt] = *dial_res;
        m_impl = std::make_unique<Impl>(Impl{client, std::move(dial_server_info)});
        rtt = dial_rtt;
    }
    co_return {rtt};
}

coro::Task<Upstream::ExchangeResult> DnscryptUpstream::apply_exchange(const ldns_pkt &request_pkt, Millis timeout) {
    Impl local_upstream;
    local_upstream = *m_impl;
    std::weak_ptr<bool> guard = m_shutdown_guard;

    utils::Timer timer;

    auto udp_reply_res = co_await local_upstream.udp_client.exchange(
            request_pkt, local_upstream.server_info, this->config().loop,
            timeout, m_config.socket_factory, this->make_socket_parameters());
    if (guard.expired()) {
        co_return make_error(DnsError::AE_SHUTTING_DOWN);
    }
    if (udp_reply_res && ldns_pkt_tc(udp_reply_res->packet.get())) {
        tracelog_id(m_log, &request_pkt, "Truncated message was received, retrying over TCP");
        dnscrypt::Client tcp_client(utils::TP_TCP);

        timeout -= timer.elapsed<decltype(timeout)>();
        if (timeout <= decltype(timeout)(0)) {
            co_return make_error(DnsError::AE_TIMED_OUT,
                    AG_FMT("Can't retry over tcp: {}", evutil_socket_error_to_string(utils::AG_ETIMEDOUT)));
        }

        auto tcp_reply_res = co_await tcp_client.exchange(request_pkt, local_upstream.server_info,
                this->config().loop, timeout, m_config.socket_factory, this->make_socket_parameters());
        if (guard.expired()) {
            co_return make_error(DnsError::AE_SHUTTING_DOWN);
        }
        if (tcp_reply_res) {
            co_return std::move(tcp_reply_res->packet);
        } else {
            co_return make_error(DnsError::AE_INTERNAL_ERROR, tcp_reply_res.error());
        }
    }
    if (udp_reply_res) {
        co_return std::move(udp_reply_res->packet);
    } else {
        co_return make_error(DnsError::AE_INTERNAL_ERROR, udp_reply_res.error());
    }
}

SocketFactory::SocketParameters DnscryptUpstream::make_socket_parameters() const {
    SocketFactory::SocketParameters socket_parameters = {};
    socket_parameters.outbound_interface = m_options.outbound_interface;
    socket_parameters.ignore_proxy_settings = m_options.ignore_proxy_settings;
    return socket_parameters;
}

} // namespace ag::dns
