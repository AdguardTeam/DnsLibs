#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "common/utils.h"
#include "common/defs.h"
#include "common/error.h"

namespace ag {
namespace dns {

constexpr auto STAMP_URL_PREFIX_WITH_SCHEME = "sdns://";

/**
 * server_informal_properties represents informal properties about the resolver
 */
enum ServerInformalProperties : uint64_t {
    /** dnssec means resolver does DNSSEC validation */
    DNSSEC = 1u << 0,
    /** no_log means resolver does not record logs */
    NO_LOG = 1u << 1,
    /** no_filter means resolver doesn't intentionally block domains */
    NO_FILTER = 1u << 2,
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
    enum class FromStringError {
        AE_NO_STAMP_SDNS_PREFIX,
        AE_NO_STAMP_URL_PREFIX,
        AE_INVALID_STAMP,
        AE_TOO_SHORT,
        AE_UNSUPPORTED_PROTOCOL,
        AE_INVALID_HOST_PORT_FORMAT,
        AE_INVALID_ADDRESS,
        AE_INVALID_PORT,
        AE_GARBAGE_AFTER_END,
    };
    using FromStringResult = Result<ServerStamp, FromStringError>;

    /**
     * Creates string from variables stored in struct
     * @return
     */
    [[nodiscard]] std::string str() const;

    /**
     * Create a URL representing this stamp that can be used as an upstream URL.
     * @param pretty_dnscrypt if `true`, return a human-readable "URL" for DNSCrypt stamps,
     *                        although such URL can't be used as an upstream URL.
     */
    [[nodiscard]] std::string pretty_url(bool pretty_dnscrypt) const;

    /**
     * Creates stamp struct from a DNS Stamp (SDNS)
     * @param sdns SDNS string
     * @return stamp struct or error
     */
    static FromStringResult from_sdns(std::string_view sdns);

    /**
     * Creates stamp struct from URL
     * @param url URL string
     * @return stamp struct or error
     */
    static FromStringResult from_string(std::string_view url);

    /**
     * Sets server informal properties
     */
    void set_server_properties(ServerInformalProperties properties);

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
    std::optional<ServerInformalProperties> props;

    /** Stamp protocol. */
    StampProtoType proto;
};

} // namespace dns

// clang format off
template<>
struct ErrorCodeToString<dns::ServerStamp::FromStringError> {
    std::string operator()(dns::ServerStamp::FromStringError e) {
        switch (e) {
        case decltype(e)::AE_NO_STAMP_SDNS_PREFIX: return AG_FMT("Stamps are expected to start with {}", dns::STAMP_URL_PREFIX_WITH_SCHEME);
        case decltype(e)::AE_NO_STAMP_URL_PREFIX: return "Unsupported URL format: expected a valid DNS upstream URL (e.g., sdns://, https://, tls://, udp://, etc.)";
        case decltype(e)::AE_INVALID_STAMP: return "Invalid stamp";
        case decltype(e)::AE_TOO_SHORT: return "Stamp is too short";
        case decltype(e)::AE_UNSUPPORTED_PROTOCOL: return "Unsupported stamp protocol identifier";
        case decltype(e)::AE_INVALID_HOST_PORT_FORMAT: return "Can't extract host and/or port";
        case decltype(e)::AE_INVALID_ADDRESS: return "Invalid server address";
        case decltype(e)::AE_INVALID_PORT: return "Invalid server port";
        case decltype(e)::AE_GARBAGE_AFTER_END: return "Invalid stamp (garbage after end)";
        }
    }
};
// clang format on

} // namespace ag
