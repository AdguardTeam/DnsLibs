#pragma once

#include <chrono>
#include <cstdint>
#include <string>
#include <utility>
#include <functional>
#include "common/defs.h"
#include "dns_crypt_utils.h"
#include "net/socket.h"

namespace ag::dnscrypt {

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
    struct FetchResult {
        CertInfo certificate;
        Millis round_trip_time;
        ErrString error;
    };

    struct EncryptResult {
        Uint8Vector ciphertext;
        Uint8Vector client_nonce;
        ErrString error;
    };

    struct DecryptResult {
        Uint8Vector message;
        ErrString error;
    };

    /**
     * Fetch DNSCrypt certificate using server info
     * @param timeout Timeout for read/write operations (0 means infinite timeout)
     * @param socket_factory Socket factory which creates sockets for data exchange
     * @param socket_parameters Connection socket parameters
     * @return Fetch result
     */
    FetchResult fetch_current_dnscrypt_cert(Millis timeout,
                                            const SocketFactory *socket_factory, SocketFactory::SocketParameters socket_parameters);

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
    struct TxtToCertInfoResult {
        CertInfo certificate;
        ErrString error;
    };

    TxtToCertInfoResult txt_to_cert_info(const ldns_rr &answer_rr) const;

    KeyArray m_secret_key; /** Client secret key */
    KeyArray m_public_key; /** Client public key */
    Uint8Vector m_server_public_key; /** Server public key */
    std::string m_server_address; /** Server IP address */
    std::string m_provider_name; /** Provider name */
    CertInfo m_server_cert; /** Certificate info (obtained with the first unencrypted DNS request) */

    friend class Client;
};

} // namespace ag::dnscrypt
