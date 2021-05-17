#include <openssl/x509v3.h>

#include <ag_logger.h>
#include <default_verifier.h>


using namespace ag;

#if defined __APPLE__ && defined __MACH__ && TARGET_OS_IPHONE

static X509_STORE *create_ca_store() {
    assert(0);
    return nullptr;
}

#elif defined __APPLE__ && defined __MACH__

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

static X509_STORE *create_ca_store() {
    logger log = create_logger("System CA Store");
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
        SecCertificateRef current_cert = (SecCertificateRef)CFArrayGetValueAtIndex(anchors, i);
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


default_verifier::default_verifier()
    : ca_store(create_ca_store())
{}

default_verifier::~default_verifier() {
    X509_STORE_free(this->ca_store);
}

default_verifier::default_verifier(const default_verifier &other) {
    *this = other;
}

default_verifier::default_verifier(default_verifier &&other) {
    *this = std::move(other);
}

default_verifier &default_verifier::operator=(const default_verifier &other) {
    if (this == &other) {
        return *this;
    }
    X509_STORE_free(this->ca_store);
    this->ca_store = other.ca_store;
    X509_STORE_up_ref(this->ca_store);
    return *this;
}

default_verifier &default_verifier::operator=(default_verifier &&other) {
    this->ca_store = other.ca_store;
    other.ca_store = nullptr;
    return *this;
}

err_string default_verifier::verify(X509_STORE_CTX *ctx_template, std::string_view host_name) const {
    if (this->ca_store == nullptr) {
        return "CA store is not set";
    }

    if (err_string err = verify_host_name(X509_STORE_CTX_get0_cert(ctx_template), host_name);
            err.has_value()) {
        return err;
    }

    using X509_STORE_CTX_ptr = std::unique_ptr<X509_STORE_CTX, ftor<&X509_STORE_CTX_free>>;
    X509_STORE_CTX_ptr ctx_holder(X509_STORE_CTX_new());
    X509_STORE_CTX *ctx = ctx_holder.get();
    if (0 == X509_STORE_CTX_init(ctx, this->ca_store,
            X509_STORE_CTX_get0_cert(ctx_template), X509_STORE_CTX_get0_untrusted(ctx_template))) {
        return "Can't verify certificate chain: can't initialize STORE_CTX";
    }
    if (0 == X509_STORE_CTX_set_purpose(ctx, X509_PURPOSE_SSL_SERVER)) {
        return "Can't verify certificate chain: can't set STORE_CTX purpose";
    }
    if (0 >= X509_verify_cert(ctx)) {
        return X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx));
    }

    return std::nullopt;
}
