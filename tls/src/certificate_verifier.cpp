#include <certificate_verifier.h>
#include <openssl/x509v3.h>


using namespace ag;


err_string certificate_verifier::verify_host_name(X509 *certificate, std::string_view host) const {
    uint32_t flags = X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT;
    if (1 == X509_check_host(certificate, host.data(), host.length(), flags, nullptr)) {
        return std::nullopt;
    } else {
        return "Host name does not match certificate subject names";
    }
}
