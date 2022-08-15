#pragma once

#include "dns/net/certificate_verifier.h"

namespace ag::dns {

/**
 * Certificate verification event
 */
struct CertificateVerificationEvent {
    Uint8Vector certificate; /** certificate being verified */
    std::vector<Uint8Vector> chain; /** certificate chain */
};

using OnCertificateVerificationFn = std::function<ErrString(CertificateVerificationEvent)>;

class ApplicationVerifier : public CertificateVerifier {
public:
    explicit ApplicationVerifier(const OnCertificateVerificationFn &on_certificate_verification);

    static std::optional<Uint8Vector> serialize_certificate(X509 *cert);

    ErrString verify(X509_STORE_CTX *ctx, std::string_view host) const override;

private:
    OnCertificateVerificationFn m_on_certificate_verification;
};

} // namespace ag::dns
