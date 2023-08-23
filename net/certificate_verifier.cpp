#include <algorithm>
#include <openssl/x509v3.h>

#include "dns/net/certificate_verifier.h"

namespace ag::dns {

std::optional<std::string> CertificateVerifier::verify_host_name(X509 *certificate, std::string_view host) const {
    uint32_t flags = X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT;
    if (1 == X509_check_host(certificate, host.data(), host.length(), flags, nullptr)
            || 1 == X509_check_ip_asc(certificate, std::string(host).c_str(), flags)) {
        return std::nullopt;
    }
    return "Host name does not match certificate subject names";
}

static std::optional<Uint8Array<SHA256_DIGEST_LENGTH>> get_cert_hash(X509 *certificate, bool is_public_key) {
    Uint8Vector out;
    int buf_len;
    EVP_PKEY *pkey;

    if (is_public_key) {
        pkey = X509_get_pubkey(certificate);
        buf_len = i2d_PUBKEY(pkey, nullptr);
    } else {
        buf_len = i2d_X509_tbs(certificate, nullptr);
    }
    if (buf_len <= 0) {
        return std::nullopt;
    }

    out.resize(buf_len);
    auto *buffer = (unsigned char *) out.data();
    if (is_public_key) {
        i2d_PUBKEY(pkey, (unsigned char **) &buffer);
        EVP_PKEY_free(pkey);
    } else {
        i2d_X509_tbs(certificate, (unsigned char **) &buffer);
    }

    std::array<uint8_t, SHA256_DIGEST_LENGTH> hash;
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, out.data(), out.size());
    SHA256_Final((uint8_t *) hash.data(), &ctx);

    return hash;
}

static bool is_cert_find_in_fingerprints(X509 *certificate, std::span<CertFingerprint> fingerprints) {
    std::optional<Uint8Array<SHA256_DIGEST_LENGTH>> spki, tbs;
    return std::any_of(fingerprints.begin(), fingerprints.end(), [&](CertFingerprint f) {
        if (auto *spki_digest = std::get_if<SpkiSha256Digest>(&f)) {
            if (!spki.has_value()) {
                spki = get_cert_hash(certificate, true);
            }
            return spki.has_value() ? std::equal(spki_digest->data.begin(), spki_digest->data.end(), spki->data())
                                    : false;
        } else if (auto *tbs_digest = std::get_if<TbsCertSha256Digest>(&f)) {
            if (!tbs.has_value()) {
                tbs = get_cert_hash(certificate, false);
            }
            return tbs.has_value() ? std::equal(tbs_digest->data.begin(), tbs_digest->data.end(), tbs->data())
                                    : false;
        }
        return false;
    });
}

std::optional<std::string> CertificateVerifier::verify_fingerprints(
        STACK_OF(X509) *chain, std::span<CertFingerprint> fingerprints) const {
    if (fingerprints.empty()) {
        return std::nullopt;
    }

    for (size_t i = 0; i < sk_X509_num(chain); ++i) {
        X509 *certificate = sk_X509_value(chain, i);
        if (is_cert_find_in_fingerprints(certificate, fingerprints)) {
            return std::nullopt;
        }
    }

    return "Fingerprints doesn't match with any certificate in chain";
}

} // namespace ag::dns
