#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>
#include "common/defs.h"

namespace ag {

using stamp_port = uint16_t;

constexpr stamp_port DEFAULT_DOH_PORT = 443;
constexpr stamp_port DEFAULT_DOT_PORT = 853;
constexpr stamp_port DEFAULT_DOQ_PORT = 853;
constexpr stamp_port DEFAULT_PLAIN_PORT = 53;
constexpr auto STAMP_URL_PREFIX_WITH_SCHEME = "sdns://";

/**
 * server_informal_properties represents informal properties about the resolver
 */
enum server_informal_properties : uint64_t {
    /** dnssec means resolver does DNSSEC validation */
    DNSSEC = 1 << 0,
    /** no_log means resolver does not record logs */
    NO_LOG = 1 << 1,
    /** no_filter means resolver doesn't intentionally block domains */
    NO_FILTER = 1 << 2,
};

/**
 * stamp_proto_type is a stamp protocol type
 */
enum class stamp_proto_type : uint8_t {
    /** plain is plain DNS */
    PLAIN,
    /** dnscrypt is DNSCrypt */
    DNSCRYPT,
    /** doh is DNS-over-HTTPS */
    DOH,
    /** tls is DNS-over-TLS */
    TLS,
    /** doq is DNS-over-QUIC */
    DOQ,
};

/**
 * server_stamp is the DNS stamp representation
 */
struct server_stamp {
    using from_str_result = std::pair<server_stamp, ErrString>;

    /**
     * Creates string from variables stored in struct
     * @return
     */
    std::string str() const;

    /**
     * Create a URL representing this stamp that can be used as an upstream URL.
     * @param pretty_dnscrypt if `true`, return a human-readable "URL" for DNSCrypt stamps,
     *                        although such URL can't be used as an upstream URL.
     */
    std::string pretty_url(bool pretty_dnscrypt) const;

    /**
     * Creates stamp struct from URL
     * @param url URL string
     * @return stamp struct or error
     */
    static from_str_result from_string(std::string_view url);

    /** Server address with port */
    std::string server_addr_str;

    /** The DNSCrypt provider’s Ed25519 public key, as 32 raw bytes. Empty for other types. */
    std::vector<uint8_t> server_pk;

    /** Hash is the SHA256 digest of one of the TBS certificate found in the validation chain, typically
     * the certificate used to sign the resolver’s certificate. Multiple hashes can be provided for seamless
     * rotations. */
    std::vector<std::vector<uint8_t>> hashes;

    /**
     * Provider means different things depending on the stamp type
     * DNSCrypt: the DNSCrypt provider name
     * DOH and DOT: server's hostname
     * Plain DNS: not specified
     */
    std::string provider_name;

    /** Path is the HTTP path, and it has a meaning for DoH stamps only. */
    std::string path;

    /** Server properties (DNSSec, NoLog, NoFilter). */
    server_informal_properties props;

    /** Stamp protocol. */
    stamp_proto_type proto;
};

} // namespace ag
