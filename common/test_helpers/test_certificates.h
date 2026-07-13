#pragma once

// Shared, header-only test-certificate kit for encrypted-protocol (DoT/DoH/DoQ/
// DoH3) loopback servers and SPKI-fingerprint pinning tests. Generates a
// self-signed X.509 certificate + EC P-256 private key programmatically on first
// use (cached for the process lifetime), with loader helpers that return owning
// OpenSSL handles, a compute_spki_hash() utility, and a TestCertificateVerifier
// with configurable verification modes.
//
// This header adds no production code and performs no network I/O: all material
// is generated in-process via BoringSSL (this repo builds against BoringSSL,
// OPENSSL_IS_BORINGSSL). It is intended for inclusion by test targets that
// already link OpenSSL transitively (via dnslibs_net / upstream).
//
// The certificate/key pair is regenerated (with a fresh random key) on every
// process start, so the SPKI digest varies across runs but is stable within a
// single run: every call in the same process returns handles that share one
// underlying cert/key (refcounted), and compute_spki_hash() always returns the
// same digest. This is all the loopback-test/spki-pinning tests require.

#include <openssl/asn1.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>

#include "common/base64.h"                // encode_to_base64 (base64 SPKI string for fingerprints)
#include "common/utils.h"                 // UniquePtr, Uint8Vector
#include "dns/net/certificate_verifier.h" // CertificateVerifier, CertFingerprint, SpkiSha256Digest

namespace ag::test {

namespace detail {

// Certificate validity span (seconds). The cert is generated fresh per test
// run and only needs to cover it, so one hour is ample. Applied via
// X509_gmtime_adj().
constexpr long CERT_VALIDITY_SECS = 60L * 60;

// Host name embedded in CN and SAN of the generated certificate.
constexpr std::string_view HOST_NAME = "localhost";

// Common name of the second (chain) cert. It is never hostname-checked (it is
// served only as an extra chain certificate), so the value is cosmetic.
constexpr std::string_view CHAIN_HOST_NAME = "chain-ca";

// Bundles the process-lifetime cert/key pair, its precomputed SPKI digest, a
// second self-signed "chain" cert (added to the server's certificate chain so
// SPKI-pinning tests can pin a non-leaf SPKI, the "second fingerprint in
// chain" case), the chain cert's SPKI digest, and the SHA-256 of the leaf
// cert's TBS region (for DNS-stamp "hashes", which pin TBS, not SPKI).
// Built once per process by generate_server_material() and cached by
// server_material(); callers receive refcounted owning handles derived from
// these masters (see load_server_cert/key).
struct ServerMaterial {
    ag::UniquePtr<X509, &X509_free> cert;
    ag::UniquePtr<EVP_PKEY, &EVP_PKEY_free> key;
    ag::dns::SpkiSha256Digest spki_digest{};
    ag::UniquePtr<X509, &X509_free> chain_cert;
    ag::UniquePtr<EVP_PKEY, &EVP_PKEY_free> chain_key;
    ag::dns::SpkiSha256Digest chain_spki_digest{};
    ag::Uint8Vector tbs_digest;
};

// Computes the SHA-256 of an EVP_PKEY's SubjectPublicKeyInfo (DER-encode the
// SPKI, then hash). Mirrors CertificateVerifier's public-key pin path
// (certificate_verifier.cpp: get_cert_hash(is_public_key=true)). Returns an
// all-zero digest if `pkey` is null or encoding fails; callers that feed the
// result into a pinned fingerprint are expected to run only after a successful
// key generation, so failure leaves the (cached) material unusable and the
// loopback tests would fail fast at handshake time instead.
inline ag::dns::SpkiSha256Digest compute_spki_digest_for(EVP_PKEY *pkey) {
    ag::dns::SpkiSha256Digest digest{};
    if (pkey == nullptr) {
        return digest;
    }
    int len = i2d_PUBKEY(pkey, nullptr);
    if (len <= 0) {
        return digest;
    }
    ag::Uint8Vector der(static_cast<size_t>(len), 0);
    unsigned char *out = der.data();
    i2d_PUBKEY(pkey, &out);
    ag::UniquePtr<EVP_MD_CTX, EVP_MD_CTX_free> md_ctx{EVP_MD_CTX_new()};
    uint32_t hash_len = static_cast<uint32_t>(digest.data.size());
    EVP_Digest(der.data(), der.size(), digest.data.data(), &hash_len, EVP_sha256(), nullptr);
    return digest;
}

// Generates a fresh EC P-256 key pair and a self-signed v3 X.509 certificate
// (CN=localhost, SAN: DNS:localhost + IP:127.0.0.1) valid for one hour, signed
// with the generated key. Also precomputes the SHA-256 of the
// SubjectPublicKeyInfo so compute_spki_hash() is O(1) and stable across calls.
// On any OpenSSL failure returns a result holding null handles; callers (the
// cached accessor and the loaders) propagate that as nullptr.
inline ServerMaterial generate_server_material() {
    ServerMaterial m;

    // --- EC P-256 key generation ---
    ag::UniquePtr<EVP_PKEY_CTX, &EVP_PKEY_CTX_free> kctx{EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr)};
    if (kctx == nullptr || EVP_PKEY_keygen_init(kctx.get()) <= 0
            || EVP_PKEY_CTX_set_ec_paramgen_curve_nid(kctx.get(), NID_X9_62_prime256v1) <= 0) {
        return m;
    }
    EVP_PKEY *pkey_raw = nullptr;
    if (EVP_PKEY_keygen(kctx.get(), &pkey_raw) <= 0 || pkey_raw == nullptr) {
        return m;
    }
    m.key.reset(pkey_raw);

    // --- self-signed v3 certificate ---
    ag::UniquePtr<X509, &X509_free> cert{X509_new()};
    if (cert == nullptr) {
        return m;
    }
    // X509 version is 0-indexed: 2 == v3 (required to carry extensions).
    if (X509_set_version(cert.get(), 2) != 1) {
        return m;
    }
    ASN1_INTEGER *serial = X509_get_serialNumber(cert.get());
    if (serial == nullptr || ASN1_INTEGER_set(serial, 1) != 1) {
        return m;
    }
    if (X509_gmtime_adj(X509_get_notBefore(cert.get()), 0) == nullptr
            || X509_gmtime_adj(X509_get_notAfter(cert.get()), CERT_VALIDITY_SECS) == nullptr) {
        return m;
    }
    if (X509_set_pubkey(cert.get(), pkey_raw) != 1) {
        return m;
    }

    // Subject name with CN=localhost; issuer == subject (self-signed).
    X509_NAME *name = X509_get_subject_name(cert.get());
    if (name == nullptr) {
        return m;
    }
    if (X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char *>(HOST_NAME.data()),
                static_cast<int>(HOST_NAME.size()), -1, 0)
            != 1) {
        return m;
    }
    if (X509_set_issuer_name(cert.get(), name) != 1) {
        return m;
    }

    // SAN: DNS:localhost + IP:127.0.0.1, so hostname verification for the
    // loopback server's host succeeds. The v3 context lets the extension
    // resolver resolve relative references (none here, but kept for parity
    // with the usual generation recipe).
    X509V3_CTX v3_ctx{};
    X509V3_set_ctx(&v3_ctx, cert.get(), cert.get(), nullptr, nullptr, 0);
    // BoringSSL does not export X509V3_EXT_conf_nid (only its _nconf_nid
    // counterpart); conf=NULL is documented as allowed for literal SAN values.
    X509_EXTENSION *san_ext =
            X509V3_EXT_nconf_nid(nullptr, &v3_ctx, NID_subject_alt_name, "DNS:localhost,IP:127.0.0.1");
    if (san_ext == nullptr) {
        return m;
    }
    int added = X509_add_ext(cert.get(), san_ext, -1);
    X509_EXTENSION_free(san_ext);
    if (added != 1) {
        return m;
    }

    if (X509_sign(cert.get(), pkey_raw, EVP_sha256()) == 0) {
        return m;
    }
    m.cert = std::move(cert);

    // --- precompute SPKI SHA-256 (mirrors CertificateVerifier's public-key path) ---
    int len = i2d_PUBKEY(pkey_raw, nullptr);
    if (len <= 0) {
        return m;
    }
    ag::Uint8Vector der(static_cast<size_t>(len), 0);
    unsigned char *out = (unsigned char *) der.data();
    i2d_PUBKEY(pkey_raw, &out);
    ag::UniquePtr<EVP_MD_CTX, EVP_MD_CTX_free> md_ctx{EVP_MD_CTX_new()};
    uint32_t hash_len = static_cast<uint32_t>(m.spki_digest.data.size());
    EVP_Digest(der.data(), der.size(), m.spki_digest.data.data(), &hash_len, EVP_sha256(), nullptr);

    // --- second self-signed "chain" cert with a distinct key, added to the
    // server's certificate chain so SPKI-pinning tests can pin a non-leaf
    // SPKI (the "second fingerprint in chain" case). It is never the leaf, so
    // its hostname/SAN are irrelevant. ---
    ag::UniquePtr<EVP_PKEY_CTX, &EVP_PKEY_CTX_free> ckctx{EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr)};
    if (ckctx == nullptr || EVP_PKEY_keygen_init(ckctx.get()) <= 0
            || EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ckctx.get(), NID_X9_62_prime256v1) <= 0) {
        return m;
    }
    EVP_PKEY *chain_pkey_raw = nullptr;
    if (EVP_PKEY_keygen(ckctx.get(), &chain_pkey_raw) <= 0 || chain_pkey_raw == nullptr) {
        return m;
    }
    m.chain_key.reset(chain_pkey_raw);

    ag::UniquePtr<X509, &X509_free> chain_cert{X509_new()};
    if (chain_cert != nullptr && X509_set_version(chain_cert.get(), 2) == 1 &&
            [&] {
                ASN1_INTEGER *serial = X509_get_serialNumber(chain_cert.get());
                return serial != nullptr && ASN1_INTEGER_set(serial, 2) == 1;
            }()
            && X509_gmtime_adj(X509_get_notBefore(chain_cert.get()), 0) != nullptr
            && X509_gmtime_adj(X509_get_notAfter(chain_cert.get()), CERT_VALIDITY_SECS) != nullptr
            && X509_set_pubkey(chain_cert.get(), chain_pkey_raw) == 1) {
        X509_NAME *cname = X509_get_subject_name(chain_cert.get());
        if (cname != nullptr
                && X509_NAME_add_entry_by_txt(cname, "CN", MBSTRING_ASC,
                           reinterpret_cast<const unsigned char *>(CHAIN_HOST_NAME.data()),
                           static_cast<int>(CHAIN_HOST_NAME.size()), -1, 0)
                        == 1
                && X509_set_issuer_name(chain_cert.get(), cname) == 1
                && X509_sign(chain_cert.get(), chain_pkey_raw, EVP_sha256()) != 0) {
            m.chain_cert = std::move(chain_cert);
        }
    }

    // Precompute the chain cert's SPKI SHA-256.
    m.chain_spki_digest = compute_spki_digest_for(chain_pkey_raw);

    // --- precompute SHA-256 of the leaf cert's TBS region (for DNS-stamp
    // "hashes", which pin the TBS, not the SPKI). Mirrors
    // CertificateVerifier::verify_fingerprints' TBS path. ---
    {
        int tbs_len =
#ifdef OPENSSL_IS_BORINGSSL
                i2d_X509_tbs(m.cert.get(), nullptr);
#else
                i2d_re_X509_tbs(m.cert.get(), nullptr);
#endif
        if (tbs_len > 0) {
            ag::Uint8Vector tbs_der(static_cast<size_t>(tbs_len), 0);
            unsigned char *tbs_out = tbs_der.data();
#ifdef OPENSSL_IS_BORINGSSL
            i2d_X509_tbs(m.cert.get(), &tbs_out);
#else
            i2d_re_X509_tbs(m.cert.get(), &tbs_out);
#endif
            m.tbs_digest.resize(SHA256_DIGEST_LENGTH);
            uint32_t tbs_hash_len = SHA256_DIGEST_LENGTH;
            EVP_Digest(tbs_der.data(), tbs_der.size(), m.tbs_digest.data(), &tbs_hash_len, EVP_sha256(), nullptr);
        }
    }

    return m;
}

// Returns a reference to the process-lifetime cert/key/digest triple, generating
// it on first use. Thread-safe initialization is guaranteed by the C++ function-
// local static initialization rules; the masters are never freed before exit.
inline const ServerMaterial &server_material() {
    static const ServerMaterial m = generate_server_material();
    return m;
}

} // namespace detail

// Returns an owning handle to the cached server certificate. The underlying X509
// is shared (refcount bumped on handout); releasing the returned handle is safe
// and never invalidates other outstanding handles or the cache.
inline ag::UniquePtr<X509, &X509_free> load_server_cert() {
    const detail::ServerMaterial &m = detail::server_material();
    if (m.cert == nullptr || X509_up_ref(m.cert.get()) != 1) {
        return nullptr;
    }
    return ag::UniquePtr<X509, &X509_free>{m.cert.get()};
}

// Returns an owning handle to the cached server private key (refcounted; see
// load_server_cert()).
inline ag::UniquePtr<EVP_PKEY, &EVP_PKEY_free> load_server_key() {
    const detail::ServerMaterial &m = detail::server_material();
    if (m.key == nullptr || EVP_PKEY_up_ref(m.key.get()) != 1) {
        return nullptr;
    }
    return ag::UniquePtr<EVP_PKEY, &EVP_PKEY_free>{m.key.get()};
}

// Builds a fresh SSL_CTX configured for TLS_server_method() with the server
// certificate and private key loaded. ALPN selection is intentionally left to
// the caller: each protocol server sets its own ALPN via
// SSL_CTX_set_alpn_select_cb(). The returned context is ready for
// SSL_set_accept_state(). If a second (chain) cert is available, it is appended
// to the certificate chain so SPKI-pinning tests can pin a non-leaf SPKI (the
// "second fingerprint in chain" case). The chain cert is not validated against
// the leaf (they are independently self-signed); the loopback clients/tests
// either accept all certs or pin a SPKI/TBS digest, neither of which performs
// chain-trust validation, so an unrelated extra cert is harmless.
inline ag::UniquePtr<SSL_CTX, &SSL_CTX_free> load_server_ssl_ctx() {
    const detail::ServerMaterial &m = detail::server_material();
    if (m.cert == nullptr || m.key == nullptr) {
        return nullptr;
    }
    ag::UniquePtr<SSL_CTX, &SSL_CTX_free> ctx{SSL_CTX_new(TLS_server_method())};
    if (ctx == nullptr) {
        return nullptr;
    }
    if (SSL_CTX_use_certificate(ctx.get(), m.cert.get()) != 1) {
        return nullptr;
    }
    if (SSL_CTX_use_PrivateKey(ctx.get(), m.key.get()) != 1) {
        return nullptr;
    }
    // Append the chain cert so the server presents a two-cert chain.
    // SSL_CTX_add_extra_chain_cert takes ownership of the passed X509*, so bump
    // the master's refcount first (the master keeps its own reference and is
    // never freed before exit).
    if (m.chain_cert != nullptr && X509_up_ref(m.chain_cert.get()) == 1) {
        if (SSL_CTX_add_extra_chain_cert(ctx.get(), m.chain_cert.get()) != 1) {
            X509_free(m.chain_cert.get()); // undo the up_ref on failure
        }
    }
    return ctx;
}

// Computes the SHA-256 digest of the SubjectPublicKeyInfo (SPKI) of the server
// certificate, wrapped as a CertFingerprint. The returned value matches what
// CertificateVerifier::verify_fingerprints() compares against, so SPKI-pinning
// tests can pass this digest via UpstreamOptions::fingerprints and the chain
// built from this cert will match. Stable across calls within a process.
inline ag::dns::CertFingerprint compute_spki_hash() {
    return ag::dns::CertFingerprint{detail::server_material().spki_digest};
}

// Standard (non-url-safe) base64 encoding of the server cert's SPKI SHA-256,
// ready to pass as a `std::string` element of UpstreamOptions::fingerprints
// (the factory base64-decodes each entry into a SpkiSha256Digest pin). Stable
// across calls within a process.
inline std::string compute_spki_hash_base64() {
    const auto &data = detail::server_material().spki_digest.data;
    return ag::encode_to_base64(ag::Uint8View{data.data(), data.size()}, false);
}

// Standard base64 encoding of the *second* (chain) cert's SPKI SHA-256, for
// the "match second fingerprint in chain" pinning test: the server presents a
// [leaf, chain] certificate chain, and pinning this value matches the non-leaf
// (second) cert, exercising the path where verify_fingerprints() finds the
// match beyond the first certificate. Stable across calls within a process.
inline std::string compute_intermediate_spki_hash_base64() {
    const auto &data = detail::server_material().chain_spki_digest.data;
    return ag::encode_to_base64(ag::Uint8View{data.data(), data.size()}, false);
}

// Raw SHA-256 of the server cert's To-Be-Signed region, as a 32-byte vector,
// for DNS-stamp `hashes` (which pin the TBS, not the SPKI). The upstream
// factory converts each stamp hash into a TbsCertSha256Digest pin
// (upstream.cpp: parse_fingerprints / stamp.hashes handling), and
// CertificateVerifier::verify_fingerprints compares it against the chain.
// Stable across calls within a process.
inline ag::Uint8Vector compute_tbs_hash() {
    return detail::server_material().tbs_digest;
}

// A CertificateVerifier for tests with three configurable modes:
//   - ACCEPT_ALL           : always succeeds (default; for talking to our own
//                            local loopback server whose cert is in trust).
//   - VERIFY_HOSTNAME_ONLY : delegates to the inherited verify_host_name();
//                            the certificate's SAN/CN must match the host.
//   - VERIFY_FINGERPRINTS  : delegates to the inherited verify_fingerprints();
//                            a certificate in the chain must match one of the
//                            supplied pins (e.g. compute_spki_hash()).
class TestCertificateVerifier : public ag::dns::CertificateVerifier {
public:
    enum class Mode { ACCEPT_ALL, VERIFY_HOSTNAME_ONLY, VERIFY_FINGERPRINTS };

    explicit TestCertificateVerifier(Mode mode = Mode::ACCEPT_ALL)
            : m_mode(mode) {
    }

    std::optional<std::string> verify(X509_STORE_CTX *ctx, std::string_view host_name,
            std::span<ag::dns::CertFingerprint> fingerprints) const override {
        if (m_mode == Mode::ACCEPT_ALL) {
            return std::nullopt;
        }
        if (m_mode == Mode::VERIFY_HOSTNAME_ONLY) {
            return verify_host_name(X509_STORE_CTX_get0_cert(ctx), host_name);
        }
        return verify_fingerprints(X509_STORE_CTX_get0_untrusted(ctx), fingerprints);
    }

private:
    Mode m_mode;
};

} // namespace ag::test
