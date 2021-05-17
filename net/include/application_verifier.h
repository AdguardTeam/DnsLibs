#pragma once

#include <certificate_verifier.h>

namespace ag {

/**
 * Certificate verification event
 */
struct certificate_verification_event {
    std::vector<uint8_t> certificate; /** certificate being verified */
    std::vector<std::vector<uint8_t>> chain; /** certificate chain */
};

using on_certificate_verification_function = std::function<std::optional<std::string>(certificate_verification_event)>;

class application_verifier : public certificate_verifier {
public:
    explicit application_verifier(const on_certificate_verification_function &on_certificate_verification);

    static std::optional<std::vector<uint8_t>> serialize_certificate(X509 *cert);

    err_string verify(X509_STORE_CTX *ctx, std::string_view host) const override;

private:
    on_certificate_verification_function m_on_certificate_verification;
};

} // namespace ag
