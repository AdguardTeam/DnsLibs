#pragma once

#include <optional>
#include <span>
#include <string_view>
#include <variant>
#include <openssl/ssl.h>

#include "common/utils.h"


namespace ag::dns {

struct SpkiSha256Digest {
    Uint8Array<SHA256_DIGEST_LENGTH> data;
};

struct TbsCertSha256Digest {
    Uint8Array<SHA256_DIGEST_LENGTH> data;
};

using CertFingerprint = std::variant<SpkiSha256Digest, TbsCertSha256Digest>;

/**
 * An abstract verifier which encapsulates the SSL/TLS certificate verification procedure.
 * It's used in the DNS-over-HTTPS and DNS-over-TLS upstreams, for example.
 */
class CertificateVerifier {
public:
    CertificateVerifier() = default;
    virtual ~CertificateVerifier() = default;

    /**
     * Verify given certificate chain with corresponding server name and fingerprints
     * @param ctx certificate chain
     * @param host_name host name
     * @param fingerprints list of fingerprints
     * @return nullopt if verified successfully, non-nullopt otherwise
     */
    virtual std::optional<std::string> verify(
            X509_STORE_CTX *ctx, std::string_view host_name, std::span<CertFingerprint> fingerprints) const = 0;

protected:
    /**
     * Verify that given certificate matches given server name
     * @param certificate certificate object
     * @param host server name
     * @return nullopt if verified successfully, non-nullopt otherwise
     */
    virtual std::optional<std::string> verify_host_name(X509 *certificate, std::string_view host) const;

    /**
     * Verify that given certificate chain matches at least one of corresponding fingerprints:
     * Computes the Fingerprints (for the public keys/ for full certificate) found in the server’s certificate chain
     * If a computed fingerprint exactly matches one of the configured pins the chain is successfully verified.
     * @param chain certificate chain
     * @param fingerprints list of fingerprints
     * @return nullopt if verified successfully, non-nullopt otherwise
     */
    virtual std::optional<std::string> verify_fingerprints(
            STACK_OF(X509) *chain, std::span<CertFingerprint> fingerprints) const;
};

} // namespace ag::dns
