#pragma once

#include <chrono>
#include <cstdint>
#include <string>
#include <utility>
#include <functional>

#include "common/coro.h"
#include "common/defs.h"
#include "common/error.h"
#include "dns/net/socket.h"

#include "dns_crypt_utils.h"

namespace ag::dns::dnscrypt {

/**
 * Cert info contains DnsCrypt server certificate data retrieved from the server
 */
struct CertInfo {
    uint32_t serial; /** Cert serial number (the cert can be superseded by another one with a higher serial number) */
    KeyArray server_pk; /** Server public key */
    KeyArray shared_key; /** Shared key */
    ClientMagicArray magic_query;
    CryptoConstruction encryption_algorithm; /** Encryption algorithm */
    uint32_t not_before; /** Cert is valid starting from this date (epoch time) */
    uint32_t not_after; /** Cert is valid until this date (epoch time) */
};

/**
 * Server info contains DNSCrypt server information necessary for decryption/encryption
 */
struct ServerInfo {
    enum FetchError {
        AE_INVALID_PUBKEY_LENGTH,
        AE_DNS_ERROR,
        AE_NO_USABLE_CERTIFICATE,
    };
    struct FetchInfo {
        CertInfo certificate;
        Millis round_trip_time;
    };
    using FetchResult = Result<FetchInfo, FetchError>;

    enum EncryptError {
        AE_QUESTION_SECTION_IS_TOO_LARGE,
        AE_PAD_ERROR,
        AE_AEAD_SEAL_ERROR,
    };
    struct EncryptInfo {
        Uint8Vector ciphertext;
        Uint8Vector client_nonce;
    };
    using EncryptResult = Result<EncryptInfo, EncryptError>;

    enum DecryptError {
        AE_INVALID_MESSAGE_SIZE_OR_PREFIX,
        AE_UNEXPECTED_NONCE,
        AE_AEAD_OPEN_ERROR,
        AE_UNPAD_ERROR,
    };
    using DecryptResult = Result<Uint8Vector, DecryptError>;

    /**
     * Fetch DNSCrypt certificate using server info
     * @param loop Event loop
     * @param timeout Timeout for read/write operations (0 means infinite timeout)
     * @param socket_factory Socket factory which creates sockets for data exchange
     * @param socket_parameters Connection socket parameters
     * @return Fetch result
     */
    coro::Task<FetchResult> fetch_current_dnscrypt_cert(EventLoop &loop,
            Millis timeout, const SocketFactory *socket_factory, SocketFactory::SocketParameters socket_parameters);

    /**
     * Encrypt packet using server info
     * @param protocol Protocol
     * @param packet Packet to encrypt
     * @return Encryption result
     */
    EncryptResult encrypt(utils::TransportProtocol protocol, Uint8View packet) const;

    /**
     * @brief Decrypt packet using server info
     * @param proto Protocol
     * @param packet Packet to decrypt
     * @return Decryption result
     */
    DecryptResult decrypt(Uint8View encrypted, Uint8View nonce) const;

    template<typename T>
    void set_server_address(T&& value) { m_server_address = std::forward<T>(value); }

    decltype(auto) get_provider_name() const { return m_provider_name; }

    decltype(auto) get_server_cert() const { return m_server_cert; }


private:
    enum TxtToCertInfoError {
        AE_CERTIFICATE_TOO_SHORT,
        AE_INVALID_CERT_MAGIC,
        AE_UNSUPPORTED_CRYPTO_CONSTRUCTION,
        AE_INCORRECT_SIGNATURE,
        AE_CERTIFICATE_NOT_YET_VALID,
        AE_CERTIFICATE_EXPIRED,
        AE_SHARED_KEY_CALCULATION,
    };
    friend class ag::ErrorCodeToString<TxtToCertInfoError>;
    using TxtToCertInfoResult = Result<CertInfo, TxtToCertInfoError>;

    TxtToCertInfoResult txt_to_cert_info(const ldns_rr &answer_rr) const;

    KeyArray m_secret_key; /** Client secret key */
    KeyArray m_public_key; /** Client public key */
    Uint8Vector m_server_public_key; /** Server public key */
    std::string m_server_address; /** Server IP address */
    std::string m_provider_name; /** Provider name */
    CertInfo m_server_cert; /** Certificate info (obtained with the first unencrypted DNS request) */

    friend class Client;
};

} // namespace ag::dns::dnscrypt

namespace ag {

template<>
struct ErrorCodeToString<ag::dns::dnscrypt::ServerInfo::FetchError> {
    std::string operator()(ag::dns::dnscrypt::ServerInfo::FetchError e) {
        switch (e) {
        case decltype(e)::AE_INVALID_PUBKEY_LENGTH: return "Invalid public key length";
        case decltype(e)::AE_DNS_ERROR: return "DNS request for server cert info failed";
        case decltype(e)::AE_NO_USABLE_CERTIFICATE: return "No usable certificate found";
        default: return "Unknown error";
        }
    }
};

template<>
struct ErrorCodeToString<ag::dns::dnscrypt::ServerInfo::EncryptError> {
    std::string operator()(ag::dns::dnscrypt::ServerInfo::EncryptError e) {
        switch (e) {
        case decltype(e)::AE_QUESTION_SECTION_IS_TOO_LARGE: return "Question too large; cannot be padded";
        case decltype(e)::AE_PAD_ERROR: return "Pad error";
        case decltype(e)::AE_AEAD_SEAL_ERROR: return "AEAD seal error";
        default: return "Unknown error";
        }
    }
};

template<>
struct ErrorCodeToString<ag::dns::dnscrypt::ServerInfo::DecryptError> {
    std::string operator()(ag::dns::dnscrypt::ServerInfo::DecryptError e) {
        switch (e) {
        case decltype(e)::AE_INVALID_MESSAGE_SIZE_OR_PREFIX: return "Invalid message size or prefix";
        case decltype(e)::AE_UNEXPECTED_NONCE: return "Unexpected nonce";
        case decltype(e)::AE_AEAD_OPEN_ERROR: return "AEAD open error";
        case decltype(e)::AE_UNPAD_ERROR: return "Unpad error";
        default: return "Unknown error";
        }
    }
};

template<>
struct ErrorCodeToString<ag::dns::dnscrypt::ServerInfo::TxtToCertInfoError> {
    std::string operator()(ag::dns::dnscrypt::ServerInfo::TxtToCertInfoError e) {
        switch (e) {
        case decltype(e)::AE_CERTIFICATE_TOO_SHORT: return "Certificate is too short";
        case decltype(e)::AE_INVALID_CERT_MAGIC: return "Invalid cert magic";
        case decltype(e)::AE_UNSUPPORTED_CRYPTO_CONSTRUCTION: return "Unsupported crypto construction";
        case decltype(e)::AE_INCORRECT_SIGNATURE: return "Incorrect signature";
        case decltype(e)::AE_CERTIFICATE_NOT_YET_VALID: return "Certificate is not valid yet";
        case decltype(e)::AE_CERTIFICATE_EXPIRED: return "Certificate is expired";
        case decltype(e)::AE_SHARED_KEY_CALCULATION: return "Error calculating shared key";
        default: return "Unknown error";
        }
    }
};

} // namespace ag
