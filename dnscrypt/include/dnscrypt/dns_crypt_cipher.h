#pragma once

#include <cstddef>
#include <functional>
#include <type_traits>
#include <utility>
#include "common/defs.h"
#include "common/utils.h"
#include "dns_crypt_consts.h"
#include "dns_crypt_utils.h"

namespace ag::dnscrypt {

/**
 * Cipher strategy base class
 */
class Cipher {
public:
    struct SharedKeyResult {
        KeyArray shared_key;
        ErrString error;
    };

    struct SealResult {
        Uint8Vector ciphertext;
        ErrString error;
    };

    struct OpenResult {
        Uint8Vector decrypted;
        ErrString error;
    };

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

struct CreateCipherResult {
    const Cipher *cipher_ptr;
    ErrString error;
};

CreateCipherResult create_cipher(CryptoConstruction value);

template<typename F, typename... Ts>
auto apply_cipher_function(CryptoConstruction local_crypto_construction, F&& f, Ts&&... xs) {
    auto[cipher_ptr, cipher_err] = create_cipher(local_crypto_construction);
    if (cipher_err) {
        using ResultType = std::invoke_result_t<F&&, decltype(cipher_ptr), Ts&&...>;
        static constexpr utils::MakeError<ResultType> make_error;
        return make_error(std::move(cipher_err));
    }
    return std::invoke(std::forward<F>(f), cipher_ptr, std::forward<Ts>(xs)...);
}

/**
 * Define cipher_FUNCTION_NAME(crypto_construction crypto_construction, params...) function
 * with same signature and return type as in cipher virtual functions
 */
#define AG_DNSCRYPT_CIPHER_FUNCTION(FUNCTION_NAME) \
template<typename... Ts> \
auto cipher_ ## FUNCTION_NAME (CryptoConstruction CryptoConstruction, Ts&&... xs) { \
    return apply_cipher_function(CryptoConstruction, &Cipher:: FUNCTION_NAME, std::forward<Ts>(xs)...); \
}

AG_DNSCRYPT_CIPHER_FUNCTION(shared_key)
AG_DNSCRYPT_CIPHER_FUNCTION(seal)
AG_DNSCRYPT_CIPHER_FUNCTION(open)

#undef AG_DNSCRYPT_CIPHER_FUNCTION

} // namespace ag::dnscrypt
