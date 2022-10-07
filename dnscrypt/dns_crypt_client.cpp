#include <sodium.h>
#include <utility>

#include "dns/dnscrypt/dns_crypt_client.h"
#include "common/net_utils.h"
#include "common/utils.h"
#include "dns/common/net_consts.h"
#include "dns/dnscrypt/dns_crypt_consts.h"
#include "dns/dnscrypt/dns_crypt_ldns.h"
#include "dns/dnscrypt/dns_crypt_utils.h"
#include "dns/dnsstamp/dns_stamp.h"

namespace ag::dns::dnscrypt {

Client::Client(utils::TransportProtocol protocol)
        : m_protocol(protocol) {
}

coro::Task<Client::DialResult> Client::dial(std::string_view stamp_str, EventLoop &loop, Millis timeout,
        const SocketFactory *socket_factory, SocketFactory::SocketParameters socket_parameters) const {

    auto stamp_res = ServerStamp::from_string(stamp_str);
    if (stamp_res.has_error()) {
        co_return make_error(DialError::AE_STAMP_PARSE_ERROR, stamp_res.error());
    }
    if (stamp_res->proto != StampProtoType::DNSCRYPT) {
        co_return make_error(DialError::AE_BAD_PROTOCOL);
    }
    co_return co_await dial(*stamp_res, loop, timeout, socket_factory, std::move(socket_parameters));
}

coro::Task<Client::DialResult> Client::dial(const ServerStamp &stamp, EventLoop &loop, Millis timeout,
        const SocketFactory *socket_factory, SocketFactory::SocketParameters socket_parameters) const {

    ServerInfo local_server_info{};
    if (crypto_box_keypair(local_server_info.m_public_key.data(), local_server_info.m_secret_key.data()) != 0) {
        co_return make_error(DialError::AE_KEYPAIR_GENERATION_ERROR);
    }
    // Set the provider properties
    local_server_info.m_server_public_key = stamp.server_pk;
    local_server_info.m_server_address = stamp.server_addr_str;
    if (SocketAddress addr = utils::str_to_socket_address(local_server_info.m_server_address); addr.port() == 0) {
        local_server_info.m_server_address = AG_FMT("{}:{}", addr.host_str(), DEFAULT_DNSCRYPT_PORT);
    }
    local_server_info.m_provider_name = stamp.provider_name;
    if (local_server_info.m_provider_name.empty()) {
        co_return make_error(DialError::AE_EMPTY_PROVIDER_NAME);
    }
    if (local_server_info.m_provider_name.back() != '.') {
        local_server_info.m_provider_name.push_back('.');
    }
    socket_parameters.proto = m_protocol;
    // Fetch the certificate and validate it
    auto fetch_res = co_await local_server_info.fetch_current_dnscrypt_cert(
            loop, timeout, socket_factory, std::move(socket_parameters));
    if (fetch_res.has_error()) {
        co_return make_error(DialError::AE_FETCH_DNSCRYPT_CERT_ERROR, fetch_res.error());
    }
    auto &[cert_info, rtt] = fetch_res.value();
    local_server_info.m_server_cert = cert_info;
    co_return DialInfo{std::move(local_server_info), rtt};
}

coro::Task<Client::ExchangeResult> Client::exchange(const ldns_pkt &message, const ServerInfo &local_server_info, EventLoop &loop,
        Millis timeout, const SocketFactory *socket_factory, SocketFactory::SocketParameters socket_parameters) const {

    utils::Timer timer;
    auto query_res = create_ldns_buffer(message);
    if (query_res.has_error()) {
        co_return query_res.error();
    }
    auto encrypt_res = local_server_info.encrypt(
            m_protocol, Uint8View(ldns_buffer_begin(query_res->get()), ldns_buffer_position(query_res->get())));
    if (encrypt_res.has_error()) {
        co_return make_error(DnsError::AE_ENCRYPT_ERROR, encrypt_res.error());
    }
    auto &[encrypted_query, client_nonce] = encrypt_res.value();
    ldns_buffer encrypted_query_buffer = {};
    ldns_buffer_new_frm_data(&encrypted_query_buffer, encrypted_query.data(), encrypted_query.size());
    ldns_buffer_set_position(&encrypted_query_buffer, encrypted_query.size());
    socket_parameters.proto = m_protocol;
    auto [encrypted_response, exchange_rtt, exchange_err] = co_await dns_exchange(loop,
            timeout, utils::str_to_socket_address(local_server_info.m_server_address),
            encrypted_query_buffer, socket_factory, std::move(socket_parameters));
    free(ldns_buffer_export(&encrypted_query_buffer));
    if (exchange_err) {
        co_return make_error(DnsError::AE_NESTED_DNS_ERROR, exchange_err);
    }
    // Reading the response
    // In case if the server local_server_info is not valid anymore (for instance, certificate was rotated)
    // the read operation will most likely time out.
    // This might be a signal to re-dial for the server certificate.
    auto decrypt_res = local_server_info.decrypt(Uint8View(encrypted_response.data(), encrypted_response.size()),
            Uint8View(client_nonce.data(), client_nonce.size()));
    if (decrypt_res.has_error()) {
        co_return make_error(DnsError::AE_DECRYPT_ERROR, decrypt_res.error());
    }
    auto reply_pkt_res = create_ldns_pkt(decrypt_res->data(), decrypt_res->size());
    if (reply_pkt_res.has_error()) {
        co_return reply_pkt_res.error();
    }
    auto rtt = timer.elapsed<Millis>();
    co_return ExchangeInfo{std::move(reply_pkt_res.value()), rtt};
}

} // namespace ag::dns::dnscrypt
