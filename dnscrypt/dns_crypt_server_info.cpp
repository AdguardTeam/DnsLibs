#include <algorithm>
#include <iterator>
#include <utility>
#ifndef _WIN32
#include <arpa/inet.h>
#endif
#include <ldns/net.h>
#include <magic_enum/magic_enum.hpp>
#include <sodium.h>

#include "common/logger.h"
#include "common/net_utils.h"
#include "common/time_utils.h"
#include "common/utils.h"
#include "dns/dnscrypt/dns_crypt_cipher.h"
#include "dns/dnscrypt/dns_crypt_consts.h"
#include "dns/dnscrypt/dns_crypt_ldns.h"
#include "dns/dnscrypt/dns_crypt_server_info.h"
#include "dns/dnscrypt/dns_crypt_utils.h"

#include "dns_crypt_padding.h"

using std::chrono::duration_cast;

namespace ag::dns::dnscrypt {

static constexpr uint8_t CERT_MAGIC[]{0x44, 0x4e, 0x53, 0x43};
static constexpr uint8_t SERVER_MAGIC[]{0x72, 0x36, 0x66, 0x6e, 0x76, 0x57, 0x6a, 0x38};
static constexpr size_t MIN_DNS_PACKET_SIZE = 12 + 5;
/** <min-query-len> is a variable length, initially set to 256 bytes, and
 * must be a multiple of 64 bytes. (see https://dnscrypt.info/protocol)
 * Some servers do not work if padded length is less than 256. Example: Quad9
 */
static constexpr size_t MIN_UDP_QUESTION_SIZE = 256;

struct Field {
    constexpr Field(size_t offset, size_t size)
            : offset(offset)
            , size(size) {
    }
    constexpr Field(const Field &local_field, size_t size)
            : Field(local_field.end_offset(), size) {
    }
    template <typename... Ts>
    constexpr Field(size_t offset, Ts &&...xs)
            : Field(offset, (... + xs.size)) {
    }
    constexpr size_t end_offset() const {
        return offset + size;
    }

    size_t offset;
    size_t size;
};

template <typename R, typename T>
constexpr const auto &field_cref(const T &container, const Field &local_field) {
    return reinterpret_cast<const R &>(container[local_field.offset]);
}

template <typename R, size_t S, typename T>
constexpr const auto &field_c_array_cref(const T &container, const Field &local_field) {
    return reinterpret_cast<const R(&)[S]>(container[local_field.offset]);
}

static constexpr Field CERT_MAGIC_FIELD{0, std::size(CERT_MAGIC)};
static constexpr Field ES_VERSION_FIELD{CERT_MAGIC_FIELD, sizeof(CryptoConstruction)};
static constexpr Field PROTOCOL_MINOR_VERSION_FIELD{ES_VERSION_FIELD, 2};
static constexpr Field SIGNATURE_FIELD{PROTOCOL_MINOR_VERSION_FIELD, 64};
static constexpr Field RESOLVER_PK_FIELD{SIGNATURE_FIELD, KEY_SIZE};
static constexpr Field CLIENT_MAGIC_FIELD{RESOLVER_PK_FIELD, CLIENT_MAGIC_LEN};
static constexpr Field SERIAL_FIELD{CLIENT_MAGIC_FIELD, 4};
static constexpr Field TS_START_FIELD{SERIAL_FIELD, 4};
static constexpr Field TS_END_FIELD{TS_START_FIELD, 4};
static constexpr Field SIGNED_FIELD{
        RESOLVER_PK_FIELD.offset, RESOLVER_PK_FIELD, CLIENT_MAGIC_FIELD, SERIAL_FIELD, TS_START_FIELD, TS_END_FIELD};
static constexpr Field CERT_FIELD{
        0, CERT_MAGIC_FIELD, ES_VERSION_FIELD, PROTOCOL_MINOR_VERSION_FIELD, SIGNATURE_FIELD, SIGNED_FIELD};

static const ag::Logger &server_info_log() {
    static auto result = ag::Logger{"server_info"};
    return result;
}

coro::Task<ServerInfo::FetchResult> ServerInfo::fetch_current_dnscrypt_cert(EventLoop &loop,
        Millis timeout, const SocketFactory *socket_factory, SocketFactory::SocketParameters socket_parameters) {

    if (m_server_public_key.size() != crypto_sign_PUBLICKEYBYTES) {
        co_return make_error(FetchError::AE_INVALID_PUBKEY_LENGTH);
    }
    auto query = create_request_ldns_pkt(LDNS_RR_TYPE_TXT, LDNS_RR_CLASS_IN, LDNS_RD, m_provider_name,
            utils::make_optional_if(socket_parameters.proto == utils::TP_UDP, MAX_DNS_UDP_SAFE_PACKET_SIZE));
    ldns_pkt_set_random_id(query.get());
    auto [exchange_reply, exchange_rtt, exchange_err] = co_await dns_exchange_from_ldns_pkt(loop, timeout,
            ag::utils::str_to_socket_address(m_server_address), *query, socket_factory, std::move(socket_parameters));
    if (exchange_err) {
        co_return make_error(FetchError::AE_DNS_ERROR, exchange_err);
    }
    CertInfo local_cert_info{};
    ldns_rr_list *answer = ldns_pkt_answer(exchange_reply.get());
    for (size_t i = 0, e = ldns_rr_list_rr_count(answer); i < e; ++i) {
        const ldns_rr &answer_rr = *ldns_rr_list_rr(answer, i);
        auto rec_cert_info_res = txt_to_cert_info(answer_rr);
        if (rec_cert_info_res.has_error()) {
            warnlog(server_info_log(), "[{}] {}", m_provider_name, rec_cert_info_res.error()->str());
            continue;
        }
        if (rec_cert_info_res->serial < local_cert_info.serial) {
            warnlog(server_info_log(), "[{}] Superseded by a previous certificate", m_provider_name);
            continue;
        }
        if (rec_cert_info_res->serial == local_cert_info.serial) {
            if (rec_cert_info_res->encryption_algorithm > local_cert_info.encryption_algorithm) {
                warnlog(server_info_log(), "[{}] Upgrading the construction from {} to {}", m_provider_name,
                        magic_enum::enum_name(local_cert_info.encryption_algorithm),
                        magic_enum::enum_name(rec_cert_info_res->encryption_algorithm));
            } else {
                warnlog(server_info_log(), "[{}] Keeping the previous, preferred crypto construction", m_provider_name);
                continue;
            }
        }
        local_cert_info = *rec_cert_info_res;
    }
    if (local_cert_info.encryption_algorithm == CryptoConstruction::UNDEFINED) {
        co_return make_error(FetchError::AE_NO_USABLE_CERTIFICATE);
    }
    co_return FetchInfo{local_cert_info, exchange_rtt};
}

ServerInfo::EncryptResult ServerInfo::encrypt(utils::TransportProtocol local_protocol, Uint8View packet_initial) const {

    Uint8Vector packet(packet_initial.begin(), packet_initial.end());
    Uint8Vector client_nonce(HALF_NONCE_SIZE);
    randombytes_buf(client_nonce.data(), client_nonce.size());
    nonce_array nonce{};
    std::copy(client_nonce.begin(), client_nonce.end(), nonce.begin());
    auto min_question_size = QUERY_OVERHEAD + packet.size();
    if (local_protocol == utils::TP_TCP) {
        uint8_t xpad = 0;
        randombytes_buf(&xpad, sizeof xpad);
        min_question_size += xpad;
    } else {
        min_question_size = std::max(MIN_UDP_QUESTION_SIZE, min_question_size);
    }
    size_t padded_length
            = std::min(MAX_DNS_UDP_SAFE_PACKET_SIZE, (std::max(min_question_size, QUERY_OVERHEAD) + 63) & ~63u);
    if (QUERY_OVERHEAD + packet.size() + 1 > padded_length) {
        return make_error(EncryptError::AE_QUESTION_SECTION_IS_TOO_LARGE);
    }
    bool pad_success = pad(packet, padded_length - QUERY_OVERHEAD);
    if (!pad_success) {
        return make_error(EncryptError::AE_PAD_ERROR);
    }
    if (auto seal_res = cipher_seal(
                m_server_cert.encryption_algorithm, utils::make_string_view(packet), nonce, m_server_cert.shared_key);
            seal_res.has_value()) {
        auto result = utils::concat<Uint8Vector>(m_server_cert.magic_query, m_public_key, client_nonce, *seal_res);
        return EncryptInfo{std::move(result), std::move(client_nonce)};
    } else {
        return make_error(EncryptError::AE_AEAD_SEAL_ERROR, seal_res.error());
    }
}

ServerInfo::DecryptResult ServerInfo::decrypt(Uint8View encrypted, Uint8View nonce) const {

    const auto &shared_key = m_server_cert.shared_key;
    auto server_magic_len = std::size(SERVER_MAGIC);
    auto response_header_len = server_magic_len + NONCE_SIZE;
    if (encrypted.size() < response_header_len + TAG_SIZE + MIN_DNS_PACKET_SIZE
            || encrypted.size() > response_header_len + TAG_SIZE + MAX_DNS_PACKET_SIZE
            || !std::equal(std::begin(SERVER_MAGIC), std::end(SERVER_MAGIC), encrypted.begin())) {
        return make_error(DecryptError::AE_INVALID_MESSAGE_SIZE_OR_PREFIX);
    }
    auto server_nonce = utils::to_array<NONCE_SIZE>(encrypted.data() + server_magic_len);
    if (!std::equal(nonce.begin(), nonce.begin() + HALF_NONCE_SIZE, server_nonce.begin())) {
        return make_error(DecryptError::AE_UNEXPECTED_NONCE);
    }
    Uint8Vector packet;
    auto encrypted_without_header = encrypted;
    encrypted_without_header.remove_prefix(response_header_len);
    auto open_res = cipher_open(m_server_cert.encryption_algorithm, encrypted_without_header, server_nonce, shared_key);
    if (open_res.has_error()) {
        return make_error(DecryptError::AE_AEAD_OPEN_ERROR, open_res.error());
    }
    packet = std::move(open_res.value());
    bool unpad_success = unpad(packet);
    if (!unpad_success || packet.size() < MIN_DNS_PACKET_SIZE) {
        return make_error(DecryptError::AE_UNPAD_ERROR);
    }
    return packet;
}

ServerInfo::TxtToCertInfoResult ServerInfo::txt_to_cert_info(const ldns_rr &answer_rr) const {

    std::vector<Uint8View> string_data_fields;
    size_t rr_count = ldns_rr_rd_count(&answer_rr);
    string_data_fields.reserve(rr_count);
    for (size_t i = 0, e = rr_count; i < e; ++i) {
        const ldns_rdf &rdf = *ldns_rr_rdf(&answer_rr, i);
        ldns_rdf_type type = ldns_rdf_get_type(&rdf);
        if (type == LDNS_RDF_TYPE_STR) {
            // copy bytes except first one (with size)
            if (auto size = ldns_rdf_size(&rdf); size > 1) {
                string_data_fields.emplace_back(ldns_rdf_data(&rdf) + 1, size - 1);
            }
        }
    }
    auto bin_cert = utils::concat<Uint8Vector>(string_data_fields);
    // Validate the cert basic params
    if (bin_cert.size() < CERT_FIELD.size) {
        return make_error(TxtToCertInfoError::AE_CERTIFICATE_TOO_SHORT);
    }
    if (!std::equal(std::begin(CERT_MAGIC), std::end(CERT_MAGIC), bin_cert.begin() + CERT_MAGIC_FIELD.offset)) {
        return make_error(TxtToCertInfoError::AE_INVALID_CERT_MAGIC);
    }
    CertInfo local_cert_info{};
    switch (CryptoConstruction es_version{ntohs(field_cref<uint16_t>(bin_cert, ES_VERSION_FIELD))}) {
    case CryptoConstruction::X_SALSA_20_POLY_1305:
    case CryptoConstruction::X_CHACHA_20_POLY_1305:
        local_cert_info.encryption_algorithm = es_version;
        break;
    default:
        return make_error(TxtToCertInfoError::AE_UNSUPPORTED_CRYPTO_CONSTRUCTION, magic_enum::enum_name(es_version));
    }
    // Verify the server public key
    Uint8View signature(&bin_cert[SIGNATURE_FIELD.offset], SIGNATURE_FIELD.size);
    Uint8View signed_(&bin_cert[SIGNED_FIELD.offset], SIGNED_FIELD.size);
    if (crypto_sign_verify_detached(signature.data(), signed_.data(), signed_.size(), m_server_public_key.data())
            != 0) {
        return make_error(TxtToCertInfoError::AE_INCORRECT_SIGNATURE);
    }
    local_cert_info.serial = ntohl(field_cref<uint32_t>(bin_cert, SERIAL_FIELD));
    local_cert_info.not_before = ntohl(field_cref<uint32_t>(bin_cert, TS_START_FIELD));
    local_cert_info.not_after = ntohl(field_cref<uint32_t>(bin_cert, TS_END_FIELD));
    // Validate the certificate date
    auto now = duration_cast<Secs>(SystemClock::now().time_since_epoch()).count();
    if (now < local_cert_info.not_before) {
        return make_error(TxtToCertInfoError::AE_CERTIFICATE_NOT_YET_VALID, format_gmtime(Secs{local_cert_info.not_before}));
    }
    if (now > local_cert_info.not_after) {
        return make_error(TxtToCertInfoError::AE_CERTIFICATE_EXPIRED, format_gmtime(Secs{local_cert_info.not_after}));
    }
    auto server_pk = utils::to_array(field_c_array_cref<uint8_t, KEY_SIZE>(bin_cert, RESOLVER_PK_FIELD));
    auto computed_shared_key_res = cipher_shared_key(local_cert_info.encryption_algorithm, m_secret_key, server_pk);
    if (computed_shared_key_res.has_error()) {
        return make_error(TxtToCertInfoError::AE_SHARED_KEY_CALCULATION, computed_shared_key_res.error());
    }
    local_cert_info.shared_key = computed_shared_key_res.value();
    std::memcpy(local_cert_info.server_pk.data(), server_pk.data(), server_pk.size());
    std::memcpy(local_cert_info.magic_query.data(), &bin_cert[CLIENT_MAGIC_FIELD.offset],
            local_cert_info.magic_query.size());
    return local_cert_info;
}

} // namespace ag::dns::dnscrypt
