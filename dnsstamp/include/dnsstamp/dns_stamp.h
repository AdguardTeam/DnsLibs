#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>
#include "common/defs.h"

namespace ag {

using StampPort = uint16_t;

constexpr StampPort DEFAULT_DOH_PORT = 443;
constexpr StampPort DEFAULT_DOT_PORT = 853;
constexpr StampPort DEFAULT_DOQ_PORT = 8853;
constexpr StampPort DEFAULT_PLAIN_PORT = 53;
constexpr auto STAMP_URL_PREFIX_WITH_SCHEME = "sdns://";

/**
 * server_informal_properties represents informal properties about the resolver
 */
enum ServerInformalProperties : uint64_t {
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
enum class StampProtoType : uint8_t {
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
struct ServerStamp {
    using FromStringResult = std::pair<ServerStamp, ErrString>;

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
    static FromStringResult from_string(std::string_view url);

    /** Server address with port */
    std::string server_addr_str;

    /** The DNSCrypt provider’s Ed25519 public key, as 32 raw bytes. Empty for other types. */
    Uint8Vector server_pk;

    /** Hash is the SHA256 digest of one of the TBS certificate found in the validation chain, typically
     * the certificate used to sign the resolver’s certificate. Multiple hashes can be provided for seamless
     * rotations. */
    std::vector<Uint8Vector> hashes;

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
    ServerInformalProperties props;

    /** Stamp protocol. */
    StampProtoType proto;
};

} // namespace ag
