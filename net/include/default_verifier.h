#pragma once


#include <openssl/err.h>
#include <openssl/ssl.h>

#include <certificate_verifier.h>


namespace ag {


class default_verifier : public certificate_verifier {
public:
    default_verifier();
    ~default_verifier() override;

    default_verifier(const default_verifier &);
    default_verifier(default_verifier &&);
    default_verifier &operator=(const default_verifier &);
    default_verifier &operator=(default_verifier &&);

    ErrString verify(X509_STORE_CTX *ctx, std::string_view host_name) const override;

private:
    X509_STORE *ca_store = nullptr;
};


} // namespace ag
