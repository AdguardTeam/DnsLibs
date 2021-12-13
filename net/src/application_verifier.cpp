#include "application_verifier.h"

ag::application_verifier::application_verifier(const on_certificate_verification_function &on_certificate_verification)
    : m_on_certificate_verification(on_certificate_verification)
{}

std::optional<std::vector<uint8_t>> ag::application_verifier::serialize_certificate(X509 *cert) {
    std::vector<uint8_t> out;
    if (int len = i2d_X509(cert, nullptr); len <= 0) {
        return std::nullopt;
    } else {
        out.resize(len);
    }
    unsigned char *buffer = (unsigned char *)out.data();
    i2d_X509(cert, (unsigned char **)&buffer);
    return out;
}

ag::ErrString ag::application_verifier::verify(X509_STORE_CTX *ctx, std::string_view host) const {
    if (ErrString err = verify_host_name(X509_STORE_CTX_get0_cert(ctx), host); err.has_value()) {
        return err;
    }

    certificate_verification_event event = {};

    std::optional<std::vector<uint8_t>> serialized = serialize_certificate(X509_STORE_CTX_get0_cert(ctx));
    if (!serialized.has_value()) {
        return "Failed to serialize certificate";
    }
    event.certificate = std::move(serialized.value());

    STACK_OF(X509) *chain = X509_STORE_CTX_get0_untrusted(ctx);
    event.chain.reserve(sk_X509_num(chain));
    for (size_t i = 0; i < sk_X509_num(chain); ++i) {
        X509 *cert = sk_X509_value(chain, i);
        serialized = serialize_certificate(cert);
        if (serialized.has_value()) {
            event.chain.emplace_back(std::move(serialized.value()));
        } else {
            event.chain.clear();
            break;
        }
    }

    return m_on_certificate_verification(std::move(event));
}
