#pragma once

#include <cstddef>
#include <functional>
#include <type_traits>
#include <utility>

#include "common/defs.h"
#include "common/error.h"
#include "common/utils.h"

#include "dns_crypt_consts.h"
#include "dns_crypt_utils.h"

namespace ag::dns::dnscrypt {

/**
 * Cipher strategy base class
 */
class Cipher {
public:
    enum CipherError {
        AE_CREATE_CIPHER_ERROR,
        AE_SCALARMULT_ERROR,
        AE_HSALSA20_ERROR,
        AE_HCHACHA20_ERROR,
        AE_AEAD_SEAL_ERROR,
        AE_AEAD_OPEN_ERROR,
        AE_WEAK_PUBKEY,
    };
    using SharedKeyResult = Result<KeyArray, CipherError>;

    using SealResult = Result<Uint8Vector, CipherError>;

    using OpenResult = Result<Uint8Vector, CipherError>;

    Cipher() = default;
    Cipher(Cipher &) = delete;
    Cipher &operator=(Cipher &) = delete;
    virtual ~Cipher() = default;

    /**
     * Compute shared key
     * @param secret_key
     * @param public_key
     * @return Shared key result
     */
    virtual SharedKeyResult shared_key(const KeyArray &secret_key, const KeyArray &public_key) const = 0;

    /**
     * Encrypt message to ciphertext
     * @param message Message to encrypt
     * @param nonce Nonce
     * @param key Key
     * @return Seal result
     */
    virtual SealResult seal(Uint8View message, const nonce_array &nonce, const KeyArray &key) const = 0;

    /**
     * Decrypt ciphertext to message
     * @param ciphertext Ciphertext to decrypt
     * @param nonce Nonce
     * @param key Key
     * @return Open result
     */
    virtual OpenResult open(Uint8View ciphertext, const nonce_array &nonce, const KeyArray &key) const = 0;
};

enum CreateCipherError {
    AE_UNKNOWN_CIPHER,
};

using CreateCipherResult = Result<Cipher *, CreateCipherError>;

CreateCipherResult create_cipher(CryptoConstruction value);

static inline Cipher::SharedKeyResult cipher_shared_key(CryptoConstruction cc, const KeyArray &secret_key, const KeyArray &public_key) {
    auto cipher_res = create_cipher(cc);
    if (cipher_res.has_error()) {
        return make_error(Cipher::CipherError::AE_CREATE_CIPHER_ERROR, cipher_res.error());
    }
    return (*cipher_res)->shared_key(secret_key, public_key);
}

static inline Cipher::SealResult cipher_seal(CryptoConstruction cc, Uint8View message, const nonce_array &nonce, const KeyArray &key) {
    auto cipher_res = create_cipher(cc);
    if (cipher_res.has_error()) {
        return make_error(Cipher::CipherError::AE_CREATE_CIPHER_ERROR, cipher_res.error());
    }
    return (*cipher_res)->seal(message, nonce, key);
}

static inline Cipher::OpenResult cipher_open(CryptoConstruction cc, Uint8View ciphertext, const nonce_array &nonce, const KeyArray &key) {
    auto cipher_res = create_cipher(cc);
    if (cipher_res.has_error()) {
        return make_error(Cipher::CipherError::AE_CREATE_CIPHER_ERROR, cipher_res.error());
    }
    return (*cipher_res)->open(ciphertext, nonce, key);
}

} // namespace ag::dns::dnscrypt

namespace ag {

template<>
struct ErrorCodeToString<ag::dns::dnscrypt::Cipher::CipherError> {
    std::string operator()(ag::dns::dnscrypt::Cipher::CipherError e) {
        switch (e) {
        case decltype(e)::AE_CREATE_CIPHER_ERROR: return "Error creating cipher";
        case decltype(e)::AE_SCALARMULT_ERROR: return "Scalarmult error";
        case decltype(e)::AE_HSALSA20_ERROR: return "HSalsa20 error";
        case decltype(e)::AE_HCHACHA20_ERROR: return "HChacha20 error";
        case decltype(e)::AE_AEAD_SEAL_ERROR: return "AEAD seal error";
        case decltype(e)::AE_AEAD_OPEN_ERROR: return "AEAD open error";
        case decltype(e)::AE_WEAK_PUBKEY: return "Weak public key";
        default: return "Unknown error";
        }
    }
};

template<>
struct ErrorCodeToString<ag::dns::dnscrypt::CreateCipherError> {
    std::string operator()(ag::dns::dnscrypt::CreateCipherError e) {
        switch (e) {
        case decltype(e)::AE_UNKNOWN_CIPHER: return "Don't know how to make cipher with value";
        default: return "Unknown error";
        }
    }
};

} // namespace ag
