// Unit/smoke tests for common/test_helpers/test_certificates.h.
//
// Verifies that the embedded PEM material parses to non-null X509/EVP_PKEY/
// SSL_CTX owning handles, that compute_spki_hash() returns a stable non-zero
// 32-byte SPKI digest, and that TestCertificateVerifier's three modes behave
// as documented. Fully offline (no network I/O): all material is a literal in
// the header.
//
// NOTE: this file lives under upstream/test/ (not common/test/) on purpose.
// The kit links OpenSSL transitively through the upstream -> dnslibs_net chain,
// and co-locating the test with that link boundary keeps common/ free of an
// OpenSSL dependency. The header itself remains in common/test_helpers/ for
// reuse by every consuming test target.

#include <gtest/gtest.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <algorithm>
#include <cstring>
#include <vector>

#include "test_certificates.h"

namespace ag::test {
namespace {

// RAII holder bundling an X509_STORE_CTX with the store and untrusted chain it
// references, so TestCertificateVerifier can be exercised against a realistic
// "leaf + chain" setup without running a full CA verification. It is built from
// a single certificate: the leaf is the cert itself, and the untrusted chain is
// a one-element stack holding an extra reference to the same cert.
class TestStoreCtx {
public:
    explicit TestStoreCtx(X509 *cert) {
        if (cert == nullptr) {
            return;
        }
        m_store.reset(X509_STORE_new());
        m_chain = sk_X509_new_null();
        if (m_chain != nullptr) {
            X509_up_ref(cert); // the stack will X509_free() its entries on destruction.
            sk_X509_push(m_chain, cert);
        }
        m_ctx.reset(X509_STORE_CTX_new());
        if (m_store != nullptr && m_chain != nullptr && m_ctx != nullptr) {
            X509_STORE_CTX_init(m_ctx.get(), m_store.get(), cert, m_chain);
        }
    }

    ~TestStoreCtx() {
        m_ctx.reset(); // free ctx first so it no longer references chain/store.
        if (m_chain != nullptr) {
            sk_X509_pop_free(m_chain, X509_free);
        }
    }

    TestStoreCtx(const TestStoreCtx &) = delete;
    TestStoreCtx &operator=(const TestStoreCtx &) = delete;

    // The store context to pass to TestCertificateVerifier::verify(), or
    // nullptr if construction failed.
    X509_STORE_CTX *get() const {
        return m_ctx.get();
    }

private:
    ag::UniquePtr<X509_STORE, &X509_STORE_free> m_store;
    STACK_OF(X509) * m_chain { nullptr };
    ag::UniquePtr<X509_STORE_CTX, &X509_STORE_CTX_free> m_ctx;
};

// Returns true if `fp` holds a SpkiSha256Digest whose 32 bytes are all zero.
bool spki_digest_is_zero(const ag::dns::CertFingerprint &fp) {
    const auto *spki = std::get_if<ag::dns::SpkiSha256Digest>(&fp);
    if (spki == nullptr) {
        return false;
    }
    return std::all_of(spki->data.begin(), spki->data.end(), [](uint8_t b) {
        return b == 0;
    });
}

} // namespace

TEST(TestCertificatesTest, LoadersReturnNonNullHandles) {
    ag::UniquePtr<X509, &X509_free> cert = load_server_cert();
    ASSERT_NE(cert, nullptr);

    ag::UniquePtr<EVP_PKEY, &EVP_PKEY_free> key = load_server_key();
    ASSERT_NE(key, nullptr);

    ag::UniquePtr<SSL_CTX, &SSL_CTX_free> ctx = load_server_ssl_ctx();
    ASSERT_NE(ctx, nullptr);
}

TEST(TestCertificatesTest, ComputeSpkiHashIsStableAndNonZero) {
    ag::dns::CertFingerprint fp1 = compute_spki_hash();
    ag::dns::CertFingerprint fp2 = compute_spki_hash();

    const auto *spki1 = std::get_if<ag::dns::SpkiSha256Digest>(&fp1);
    ASSERT_NE(spki1, nullptr);
    ASSERT_EQ(spki1->data.size(), SHA256_DIGEST_LENGTH);
    ASSERT_FALSE(spki_digest_is_zero(fp1));

    const auto *spki2 = std::get_if<ag::dns::SpkiSha256Digest>(&fp2);
    ASSERT_NE(spki2, nullptr);
    ASSERT_EQ(std::memcmp(spki1->data.data(), spki2->data.data(), spki1->data.size()), 0);
}

TEST(TestCertificatesTest, AcceptAllModeAlwaysSucceeds) {
    ag::UniquePtr<X509, &X509_free> cert = load_server_cert();
    ASSERT_NE(cert, nullptr);
    TestStoreCtx store(cert.get());
    ASSERT_NE(store.get(), nullptr);

    std::vector<ag::dns::CertFingerprint> fps;
    TestCertificateVerifier verifier{TestCertificateVerifier::Mode::ACCEPT_ALL};
    EXPECT_FALSE(verifier.verify(store.get(), "localhost", fps).has_value());
    EXPECT_FALSE(verifier.verify(store.get(), "anything.example", fps).has_value());
}

TEST(TestCertificatesTest, DefaultModeIsAcceptAll) {
    ag::UniquePtr<X509, &X509_free> cert = load_server_cert();
    ASSERT_NE(cert, nullptr);
    TestStoreCtx store(cert.get());
    ASSERT_NE(store.get(), nullptr);

    std::vector<ag::dns::CertFingerprint> fps;
    TestCertificateVerifier verifier;
    EXPECT_FALSE(verifier.verify(store.get(), "localhost", fps).has_value());
}

TEST(TestCertificatesTest, HostnameOnlyMatchesLocalhost) {
    ag::UniquePtr<X509, &X509_free> cert = load_server_cert();
    ASSERT_NE(cert, nullptr);
    TestStoreCtx store(cert.get());
    ASSERT_NE(store.get(), nullptr);

    std::vector<ag::dns::CertFingerprint> fps;
    TestCertificateVerifier verifier{TestCertificateVerifier::Mode::VERIFY_HOSTNAME_ONLY};

    // SAN includes DNS:localhost and IP:127.0.0.1.
    EXPECT_FALSE(verifier.verify(store.get(), "localhost", fps).has_value());
    EXPECT_FALSE(verifier.verify(store.get(), "127.0.0.1", fps).has_value());
    // An unrelated host name must not match.
    EXPECT_TRUE(verifier.verify(store.get(), "evil.example", fps).has_value());
}

TEST(TestCertificatesTest, FingerprintsMatchServerSpki) {
    ag::UniquePtr<X509, &X509_free> cert = load_server_cert();
    ASSERT_NE(cert, nullptr);
    TestStoreCtx store(cert.get());
    ASSERT_NE(store.get(), nullptr);

    // Matching SPKI pin -> success.
    std::vector<ag::dns::CertFingerprint> match = {compute_spki_hash()};
    TestCertificateVerifier verifier{TestCertificateVerifier::Mode::VERIFY_FINGERPRINTS};
    EXPECT_FALSE(verifier.verify(store.get(), "", match).has_value());

    // All-zero (non-matching) pin -> failure.
    ag::dns::SpkiSha256Digest zero{};
    std::vector<ag::dns::CertFingerprint> mismatch = {ag::dns::CertFingerprint{zero}};
    EXPECT_TRUE(verifier.verify(store.get(), "", mismatch).has_value());

    // Empty pin list -> verify_fingerprints treats it as "no pin to check",
    // i.e. success (matches DefaultVerifier semantics).
    std::vector<ag::dns::CertFingerprint> empty;
    EXPECT_FALSE(verifier.verify(store.get(), "", empty).has_value());
}

} // namespace ag::test
