#include <chrono>
#include <ag_utils.h>
#include <ag_logger.h>
#include "upstream_dnscrypt.h"
#include <dns_crypt_client.h>

static const ag::logger &upstream_dnscrypt_log() {
    static auto result = ag::create_logger("ag::dnscrypt::upstream_dnscrypt");
    return result;
}

struct ag::upstream_dnscrypt::impl {
    dnscrypt::client udp_client;
    dnscrypt::server_info server_info;
};

ag::upstream_dnscrypt::upstream_dnscrypt(server_stamp &&stamp, std::chrono::milliseconds timeout) :
        m_stamp(std::move(stamp)), m_timeout(timeout)
{}

ag::upstream_dnscrypt::~upstream_dnscrypt() = default;

std::string ag::upstream_dnscrypt::address() {
    return m_stamp.server_addr_str;
}

ag::upstream_dnscrypt::exchange_result ag::upstream_dnscrypt::exchange(ldns_pkt *request_pkt) {
    static constexpr utils::make_error<exchange_result> make_error;
    if (auto setup_impl_err = setup_impl()) {
        return make_error(std::move(setup_impl_err));
    }
    auto[reply, reply_err] = apply_exchange(*request_pkt);
    if (reply_err) {
        return make_error(std::move(reply_err));
    }
    if (reply && ldns_pkt_id(reply.get()) != ldns_pkt_id(request_pkt)) {
        return make_error("Request and reply ids are not equal");
    }
    return {std::move(reply), std::nullopt};
}

ag::err_string ag::upstream_dnscrypt::setup_impl() {
    namespace chrono = std::chrono;
    auto now = chrono::duration_cast<chrono::milliseconds>(chrono::steady_clock::now().time_since_epoch()).count();
    if (!m_impl || (m_impl && m_impl->server_info.get_server_cert().not_after < now)) {
        dnscrypt::client client(m_timeout);
        auto[dial_server_info, dial_rtt, dial_err] = client.dial(m_stamp);
        if (dial_err) {
            return "Failed to fetch certificate info from " + address() + " with error: " + *dial_err;
        }
        m_impl.reset(new impl{client, std::move(dial_server_info)});
    }
    return std::nullopt;
}

ag::upstream_dnscrypt::exchange_result ag::upstream_dnscrypt::apply_exchange(ldns_pkt &request_pkt) {
    auto[udp_reply, udp_reply_rtt, udp_reply_err] = m_impl->udp_client.exchange(request_pkt, m_impl->server_info);
    if (udp_reply && ldns_pkt_tc(udp_reply.get())) {
        tracelog(upstream_dnscrypt_log(), "Truncated message was received, retrying over TCP");
        dnscrypt::client tcp_client(dnscrypt::protocol::TCP, m_timeout);
        auto[tcp_reply, tcp_reply_rtt, tcp_reply_err] = tcp_client.exchange(request_pkt, m_impl->server_info);
        return {std::move(tcp_reply), std::move(tcp_reply_err)};
    }
    return {std::move(udp_reply), std::move(udp_reply_err)};
}
