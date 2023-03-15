#pragma once

#include <optional>
#include <span>

#include "dns/net/certificate_verifier.h"

namespace ag::dns {

/**
 * Certificate verification event
 */
struct CertificateVerificationEvent {
    Uint8Vector certificate; /** certificate being verified */
    std::vector<Uint8Vector> chain; /** certificate chain */
};

using OnCertificateVerificationFn = std::function<std::optional<std::string>(CertificateVerificationEvent)>;

class ApplicationVerifier : public CertificateVerifier {
public:
    explicit ApplicationVerifier(const OnCertificateVerificationFn &on_certificate_verification);

    static std::optional<Uint8Vector> serialize_certificate(X509 *cert);

    std::optional<std::string> verify(
            X509_STORE_CTX *ctx, std::string_view host, std::span<CertFingerprint> fingerprints) const override;

private:
    OnCertificateVerificationFn m_on_certificate_verification;
};

} // namespace ag::dns
