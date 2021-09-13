#pragma once


#include <memory>
#include <variant>
#include <optional>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <ag_defs.h>
#include <ag_logger.h>
#include <certificate_verifier.h>
#include <tls_session_cache.h>


namespace ag {


class tls_codec {
public:
    struct error {
        std::string description;
    };

    struct chunk {
        uint8_vector data;
    };

    using send_encrypted_result = std::variant<chunk, error>;
    using read_decrypted_result = std::variant<chunk, error>;

    struct decrypted_bytes_written {
        size_t num;
    };
    using write_decrypted_result = std::variant<decrypted_bytes_written, error>;

    tls_codec(const certificate_verifier *cert_verifier, tls_session_cache *session_cache);
    ~tls_codec() = default;

    /**
     * Initiate the TLS session
     * @param sni server name
     * @param alpn application protocols
     * @return none if started successfully
     */
    std::optional<error> connect(const std::string &sni, std::vector<std::string> alpn);

    /**
     * Check if the codec has pending data to send via network
     */
    [[nodiscard]] bool want_send_encrypted() const;

    /**
     * Check if the codec has pending data ready to be decrypted
     */
    [[nodiscard]] bool want_read_decrypted() const;

    /**
     * Check if the TLS session is connected
     */
    [[nodiscard]] bool is_connected() const;

    /**
     * Get an encrypted data chunk to send via network
     */
    send_encrypted_result send_encrypted();

    /**
     * Feed a data chunk received from network
     */
    std::optional<error> recv_encrypted(uint8_view buffer);

    /**
     * Read a decrypted data chunk from the TLS session
     */
    read_decrypted_result read_decrypted();

    /**
     * Encrypt and send a data chunk
     */
    write_decrypted_result write_decrypted(uint8_view buffer);

private:
    const certificate_verifier *cert_verifier = nullptr;
    tls_session_cache *session_cache = nullptr;
    std::unique_ptr<SSL, ftor<&SSL_free>> ssl;
    logger log;

    static int ssl_verify_callback(X509_STORE_CTX *ctx, void *arg);
    std::optional<error> proceed_handshake();
};


} // namespace ag
