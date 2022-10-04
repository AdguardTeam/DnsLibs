#pragma once


#include <string_view>
#include <openssl/ssl.h>

#include "common/utils.h"


namespace ag::dns {

/**
 * An abstract verifier which encapsulates the SSL/TLS certificate verification procedure.
 * It's used in the DNS-over-HTTPS and DNS-over-TLS upstreams, for example.
 */
class CertificateVerifier {
public:
    CertificateVerifier() = default;
    virtual ~CertificateVerifier() = default;

    /**
     * Verify given certificate chain with corresponding server name
     * @param chain certificate chain
     * @param host_name host name
     * @return nullopt if verified successfully, non-nullopt otherwise
     */
    virtual std::optional<std::string> verify(X509_STORE_CTX *ctx, std::string_view host_name) const = 0;

protected:
    /**
     * Verify that given certificate matches given server name
     *
     * @param certificate certificate object
     * @param host server name
     * @return nullopt if verified successfully, non-nullopt otherwise
     */
    virtual std::optional<std::string> verify_host_name(X509 *certificate, std::string_view host) const;
};

} // namespace ag::dns