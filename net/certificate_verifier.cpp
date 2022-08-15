#include "dns/net/certificate_verifier.h"
#include <openssl/x509v3.h>

namespace ag::dns {

ErrString CertificateVerifier::verify_host_name(X509 *certificate, std::string_view host) const {
    uint32_t flags = X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT;
    if (1 == X509_check_host(certificate, host.data(), host.length(), flags, nullptr)
            || 1 == X509_check_ip_asc(certificate, std::string(host).c_str(), flags)) {
        return std::nullopt;
    } else {
        return "Host name does not match certificate subject names";
    }
}

} // namespace ag::dns
