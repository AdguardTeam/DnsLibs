#include <utility>
#include <sodium.h>
#include "dns_crypt_consts.h"
#include "dns_crypt_ldns.h"
#include <ag_utils.h>
#include <dns_crypt_client.h>
#include <dns_crypt_utils.h>
#include <dns_stamp.h>

/**
 * Adjusts the maximum payload size advertised in queries sent to upstream servers
 * See https://github.com/jedisct1/dnscrypt-proxy/blob/master/dnscrypt-proxy/plugin_get_set_payload_size.go
 * See here also: https://github.com/jedisct1/dnscrypt-proxy/issues/667
*/
static void ldns_pkt_adjust_payload_size(ldns_pkt &msg) {
    size_t original_max_payload_size = LDNS_MIN_BUFLEN - ag::dnscrypt::QUERY_OVERHEAD;
    if (ldns_pkt_edns(&msg) && ldns_pkt_edns_version(&msg) == 0) {
        original_max_payload_size = std::max(ag::dnscrypt::MAX_DNS_UDP_SAFE_PACKET_SIZE - ag::dnscrypt::QUERY_OVERHEAD,
                                             original_max_payload_size);
    }
    size_t max_payload_size = std::min(ag::dnscrypt::MAX_DNS_PACKET_SIZE - ag::dnscrypt::QUERY_OVERHEAD,
                                       original_max_payload_size);
    if (max_payload_size > LDNS_MIN_BUFLEN) {
        ldns_pkt_set_edns_udp_size(&msg, max_payload_size);
    }
}

ag::dnscrypt::client::client(std::chrono::milliseconds timeout, bool adjust_payload_size) :
        client(DEFAULT_PROTOCOL, timeout, adjust_payload_size)
{}

ag::dnscrypt::client::client(protocol protocol, std::chrono::milliseconds timeout, bool adjust_payload_size) :
        m_protocol(protocol),
        m_timeout(timeout),
        m_adjust_payload_size(adjust_payload_size)
{}

ag::dnscrypt::client::dial_result ag::dnscrypt::client::dial(std::string_view stamp_str) {
    static constexpr utils::make_error<dial_result> make_error;
    auto[stamp, stamp_err] = ag::server_stamp::from_string(stamp_str);
    if (stamp_err) {
        return make_error(std::move(stamp_err));
    }
    if (stamp.proto != stamp_proto_type::DNSCRYPT) {
        return make_error("Stamp is not for a DNSCrypt server");
    }
    return dial(stamp);
}

ag::dnscrypt::client::dial_result ag::dnscrypt::client::dial(const server_stamp &stamp) {
    static constexpr utils::make_error<dial_result> make_error;
    server_info local_server_info{};
    if (crypto_box_keypair(local_server_info.m_public_key.data(), local_server_info.m_secret_key.data()) != 0) {
        return make_error("Can not generate keypair");
    }
	// Set the provider properties
	local_server_info.m_server_public_key = stamp.server_pk;
    local_server_info.m_server_address = stamp.server_addr_str;
    local_server_info.m_provider_name = stamp.provider_name;
    if (local_server_info.m_provider_name.empty()) {
        return make_error("Provider name is empty");
    }
    if (local_server_info.m_provider_name.back() != '.') {
        local_server_info.m_provider_name.push_back('.');
    }
	// Fetch the certificate and validate it
	auto[cert_info, rtt, err] = local_server_info.fetch_current_dnscrypt_cert(m_protocol, m_timeout);
	if (err) {
		return make_error(std::move(err));
	}
    local_server_info.m_server_cert = cert_info;
	return {std::move(local_server_info), rtt, std::nullopt};
}

ag::dnscrypt::client::exchange_result ag::dnscrypt::client::exchange(ldns_pkt &message,
                                                                     const server_info &local_server_info) {
    static constexpr utils::make_error<exchange_result> make_error;
    utils::timer timer;
    if (m_adjust_payload_size) {
        ldns_pkt_adjust_payload_size(message);
    }
    auto[query, create_ldns_buffer_err] = create_ldns_buffer(message);
    if (create_ldns_buffer_err) {
        return make_error(std::move(create_ldns_buffer_err));
    }
    auto[encrypted_query, client_nonce, encrypt_err] = local_server_info.encrypt(
            m_protocol, uint8_view(ldns_buffer_begin(query.get()), ldns_buffer_position(query.get())));
    if (encrypt_err) {
        return make_error(std::move(encrypt_err));
    }
    ldns_buffer_ptr encrypted_query_buffer(ldns_buffer_new(0));
    ldns_buffer_new_frm_data(encrypted_query_buffer.get(), encrypted_query.data(), encrypted_query.size());
    ldns_buffer_set_position(encrypted_query_buffer.get(), encrypted_query.size());
    auto[encrypted_response, encrypted_response_size, exchange_rtt, exchange_err] =
            dns_exchange_allocated(m_timeout, socket_address(local_server_info.m_server_address),
                                   *encrypted_query_buffer, m_protocol);
    if (exchange_err) {
        return make_error(std::move(exchange_err));
    }
	// Reading the response
	// In case if the server local_server_info is not valid anymore (for instance, certificate was rotated)
	// the read operation will most likely time out.
	// This might be a signal to re-dial for the server certificate.
    auto[decrypted, decrypt_err] = local_server_info.decrypt(
            uint8_view(encrypted_response.get(), encrypted_response_size),
            uint8_view(client_nonce.data(), client_nonce.size()));
    if (decrypt_err) {
        return make_error(std::move(decrypt_err));
    }
    auto[reply_pkt_unique_ptr, reply_err] = create_ldns_pkt(decrypted.data(), decrypted.size());
    if (reply_err) {
        return make_error(std::move(reply_err));
    }
    auto rtt = timer.elapsed<std::chrono::milliseconds>();
    return {std::move(reply_pkt_unique_ptr), rtt, std::nullopt};
}
