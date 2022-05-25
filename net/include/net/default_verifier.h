#pragma once


#include <openssl/err.h>
#include <openssl/ssl.h>

#include "certificate_verifier.h"


namespace ag {


class DefaultVerifier : public CertificateVerifier {
public:
    DefaultVerifier();
    ~DefaultVerifier() override;

    DefaultVerifier(const DefaultVerifier &);
    DefaultVerifier(DefaultVerifier &&) noexcept;
    DefaultVerifier &operator=(const DefaultVerifier &);
    DefaultVerifier &operator=(DefaultVerifier &&) noexcept;

    ErrString verify(X509_STORE_CTX *ctx, std::string_view host_name) const override;

private:
    X509_STORE *m_ca_store = nullptr;
};


} // namespace ag
