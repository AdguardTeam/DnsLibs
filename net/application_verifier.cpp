#include "dns/net/application_verifier.h"

namespace ag::dns {

ApplicationVerifier::ApplicationVerifier(const OnCertificateVerificationFn &on_certificate_verification)
        : m_on_certificate_verification(on_certificate_verification) {
}

std::optional<Uint8Vector> ApplicationVerifier::serialize_certificate(X509 *cert) {
    Uint8Vector out;
    if (int len = i2d_X509(cert, nullptr); len <= 0) {
        return std::nullopt;
    } else {
        out.resize(len);
    }
    unsigned char *buffer = (unsigned char *) out.data();
    i2d_X509(cert, (unsigned char **) &buffer);
    return out;
}

std::optional<std::string> ApplicationVerifier::verify(
        X509_STORE_CTX *ctx, std::string_view host, std::span<CertFingerprint> fingerprints) const {
    if (auto err = verify_host_name(X509_STORE_CTX_get0_cert(ctx), host)) {
        return err;
    }

    CertificateVerificationEvent event = {};

    std::optional<Uint8Vector> serialized = serialize_certificate(X509_STORE_CTX_get0_cert(ctx));
    if (!serialized.has_value()) {
        return "Failed to serialize certificate";
    }
    event.certificate = std::move(serialized.value());

    STACK_OF(X509) *chain = X509_STORE_CTX_get0_untrusted(ctx);
    event.chain.reserve(sk_X509_num(chain));
    for (size_t i = 0; i < size_t(sk_X509_num(chain)); ++i) {
        X509 *cert = sk_X509_value(chain, i);
        serialized = serialize_certificate(cert);
        if (serialized.has_value()) {
            event.chain.emplace_back(std::move(serialized.value()));
        } else {
            event.chain.clear();
            break;
        }
    }

    if (auto err = verify_fingerprints(chain, fingerprints)) {
        return err;
    }
    return m_on_certificate_verification(std::move(event));
}

} // namespace ag::dns
