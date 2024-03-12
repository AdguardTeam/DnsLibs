#include <cassert>
#include <openssl/x509v3.h>

#include "common/logger.h"
#include "dns/net/default_verifier.h"

namespace ag::dns {

#if defined __APPLE__ && defined __MACH__ && TARGET_OS_IPHONE

static X509_STORE *create_ca_store() {
    assert(0);
    return nullptr;
}

#elif defined __APPLE__ && defined __MACH__

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

static X509_STORE *create_ca_store() {
    Logger log{"System CA Store"};
    X509_STORE *store = X509_STORE_new();
    if (store == nullptr) {
        warnlog(log, "Cannot initialize OpenSSL certificate store");
        return nullptr;
    }

    CFArrayRef anchors;
    if (OSStatus r = SecTrustCopyAnchorCertificates(&anchors); r != errSecSuccess) {
        return nullptr;
    }

    for (CFIndex i = 0; i < CFArrayGetCount(anchors); i++) {
        SecCertificateRef current_cert = (SecCertificateRef) CFArrayGetValueAtIndex(anchors, i);
        if (current_cert == nullptr) {
            continue;
        }

        CFDataRef cert_data = SecCertificateCopyData(current_cert);
        if (cert_data == nullptr) {
            continue;
        }

        X509 *xcert = nullptr;
        const uint8_t *ptr = CFDataGetBytePtr(cert_data);
        d2i_X509(&xcert, &ptr, CFDataGetLength(cert_data));
        if (xcert != nullptr) {
            if (0 == X509_STORE_add_cert(store, xcert)) {
                warnlog(log, "Failed to add ca_cert to OpenSSL certificate store");
            }
            X509_free(xcert);
        }

        CFRelease(cert_data);
    }

    CFRelease(anchors);

    return store;
}

#else

static X509_STORE *create_ca_store() {
    X509_STORE *store = X509_STORE_new();
    X509_STORE_set_default_paths(store);
    return store;
}

#endif // defined __APPLE__ && defined __MACH__

DefaultVerifier::DefaultVerifier()
        : m_ca_store(create_ca_store()) {
}

DefaultVerifier::~DefaultVerifier() {
    X509_STORE_free(m_ca_store);
}

DefaultVerifier::DefaultVerifier(const DefaultVerifier &other) {
    *this = other;
}

DefaultVerifier::DefaultVerifier(DefaultVerifier &&other) noexcept {
    *this = std::move(other);
}

DefaultVerifier &DefaultVerifier::operator=(const DefaultVerifier &other) {
    if (this == &other) {
        return *this;
    }
    X509_STORE_free(m_ca_store);
    m_ca_store = other.m_ca_store;
    X509_STORE_up_ref(m_ca_store);
    return *this;
}

DefaultVerifier &DefaultVerifier::operator=(DefaultVerifier &&other) noexcept {
    m_ca_store = other.m_ca_store;
    other.m_ca_store = nullptr;
    return *this;
}

std::optional<std::string> DefaultVerifier::verify(
        X509_STORE_CTX *ctx_template, std::string_view host_name, std::span<CertFingerprint> fingerprints) const {
    if (m_ca_store == nullptr) {
        return "CA store is not set";
    }

    if (auto err = verify_host_name(X509_STORE_CTX_get0_cert(ctx_template), host_name)) {
        return err;
    }

    using X509_STORE_CTX_ptr = ag::UniquePtr<X509_STORE_CTX, &X509_STORE_CTX_free>;
    X509_STORE_CTX_ptr ctx_holder(X509_STORE_CTX_new());
    X509_STORE_CTX *ctx = ctx_holder.get();
    if (X509_STORE_CTX_init(
                ctx, m_ca_store, X509_STORE_CTX_get0_cert(ctx_template), X509_STORE_CTX_get0_untrusted(ctx_template))
            == 0) {
        return "Can't verify certificate chain: can't initialize STORE_CTX";
    }
    if (0 == X509_STORE_CTX_set_purpose(ctx, X509_PURPOSE_SSL_SERVER)) {
        return "Can't verify certificate chain: can't set STORE_CTX purpose";
    }
    if (0 >= X509_verify_cert(ctx)) {
        return X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx));
    }

    if (auto err = verify_fingerprints(X509_STORE_CTX_get0_untrusted(ctx), fingerprints)) {
        return err;
    }
    return std::nullopt;
}

} // namespace ag::dns
