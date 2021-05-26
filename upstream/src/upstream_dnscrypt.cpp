#include <chrono>
#include <memory>
#include <ag_utils.h>
#include <sodium.h>
#include "upstream_dnscrypt.h"
#include <dns_crypt_client.h>

#define tracelog_id(log_, pkt_, fmt_, ...) tracelog(log_, "[{}] " fmt_, ldns_pkt_id(pkt_), ##__VA_ARGS__)

struct initializer {
    initializer() {
        if (sodium_init() == -1) {
            SPDLOG_ERROR("Failed to initialize libsodium");
        }
    }
};

struct ag::upstream_dnscrypt::impl {
    dnscrypt::client udp_client;
    dnscrypt::server_info server_info;
};

static ag::upstream_options make_dnscrypt_options(const ag::server_stamp &stamp, const ag::upstream_options &opts) {
    ag::upstream_options converted = opts;
    converted.address = stamp.server_addr_str;
    return converted;
}

ag::upstream_dnscrypt::upstream_dnscrypt(server_stamp &&stamp,
                                         const upstream_options &opts,
                                         const upstream_factory_config &config)
    : upstream(make_dnscrypt_options(stamp, opts), config)
    , m_stamp(std::move(stamp))
{
    static const initializer ensure_initialized;
}

ag::err_string ag::upstream_dnscrypt::init() {
    return std::nullopt;
}

ag::upstream_dnscrypt::~upstream_dnscrypt() = default;

ag::upstream_dnscrypt::exchange_result ag::upstream_dnscrypt::exchange(ldns_pkt *request_pkt) {
    tracelog_id(m_log, request_pkt, "Started");
    static constexpr utils::make_error<exchange_result> make_error;
    setup_result result = setup_impl();
    if (result.error.has_value()) {
        return make_error(std::move(result.error));
    }
    if (this->m_options.timeout < result.rtt) {
        return make_error(AG_FMT("Certificate fetch took too much time: {}ms", result.rtt.count()));
    }
    auto[reply, reply_err] = apply_exchange(*request_pkt, this->m_options.timeout - result.rtt);
    if (reply_err) {
        return make_error(std::move(reply_err));
    }
    if (reply && ldns_pkt_id(reply.get()) != ldns_pkt_id(request_pkt)) {
        return make_error("Request and reply ids are not equal");
    }
    tracelog_id(m_log, request_pkt, "Finished");
    return {std::move(reply), std::nullopt};
}

ag::upstream_dnscrypt::setup_result ag::upstream_dnscrypt::setup_impl() {
    namespace chrono = std::chrono;
    chrono::milliseconds rtt(0);
    auto now = chrono::duration_cast<chrono::milliseconds>(chrono::steady_clock::now().time_since_epoch()).count();
    if (std::scoped_lock l(m_guard);
            !m_impl || m_impl->server_info.get_server_cert().not_after < now) {
        ag::dnscrypt::client client;
        auto[dial_server_info, dial_rtt, dial_err] = client.dial(
                m_stamp, m_options.timeout, m_config.socket_factory, this->make_socket_parameters());
        if (dial_err) {
            return { rtt,
                AG_FMT("Failed to fetch certificate info from {} with error: {}", this->m_options.address, *dial_err) };
        }
        m_impl = std::make_unique<impl>(impl{client, std::move(dial_server_info)});
        rtt = dial_rtt;
    }
    return { rtt };
}

ag::upstream_dnscrypt::exchange_result ag::upstream_dnscrypt::apply_exchange(ldns_pkt &request_pkt,
        std::chrono::milliseconds timeout) {
    impl local_upstream;
    {
        std::scoped_lock l(m_guard);
        local_upstream = *m_impl;
    }

    utils::timer timer;

    auto[udp_reply, udp_reply_rtt, udp_reply_err] = local_upstream.udp_client.exchange(request_pkt,
            local_upstream.server_info, timeout, m_config.socket_factory, this->make_socket_parameters());

    if (udp_reply && ldns_pkt_tc(udp_reply.get())) {
        tracelog_id(m_log, &request_pkt, "Truncated message was received, retrying over TCP");
        dnscrypt::client tcp_client(utils::TP_TCP);

        timeout -= timer.elapsed<decltype(timeout)>();
        if (timeout <= decltype(timeout)(0)) {
            return { nullptr, evutil_socket_error_to_string(utils::AG_ETIMEDOUT) };
        }

        auto[tcp_reply, tcp_reply_rtt, tcp_reply_err] = tcp_client.exchange(request_pkt,
                local_upstream.server_info, timeout, m_config.socket_factory, this->make_socket_parameters());
        return {std::move(tcp_reply), std::move(tcp_reply_err)};
    }
    return {std::move(udp_reply), std::move(udp_reply_err)};
}

ag::socket_factory::socket_parameters ag::upstream_dnscrypt::make_socket_parameters() const {
    socket_factory::socket_parameters socket_parameters = {};
    socket_parameters.outbound_interface = m_options.outbound_interface;
    socket_parameters.ignore_proxy_settings = m_options.ignore_proxy_settings;
    return socket_parameters;
}
