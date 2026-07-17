// adig_cli — EDNS-layer & IP-address helpers for the pure adig CLI logic.
//
// This translation unit holds the EDNS option encoding/decoding, the EDNS
// option-text formatter, the reverse-DNS / opcode / TTL helpers and the shared
// parse_ip_addr IP-literal parser (declared in adig_cli_internal.h). See
// adig_cli.h for the public interface and adig_cli.cpp for argument parsing.

#include "adig_cli.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include <fmt/format.h>
#include <ldns/ldns.h>

#include "adig_cli_internal.h"

namespace ag::adig {
namespace {

// RAII wrapper for ldns malloc'd strings (char pointers returned by
// ldns_rdf2str, ldns_rr_type2str, etc.) — they must be freed with free().
using ag::AllocatedPtr;

} // namespace

// Parse an IPv4/IPv6 literal into its EDNS family code (1 / 2) and address
// bytes. Returns nullopt for anything that is not a valid address literal.
// Used by both make_reverse_name (reverse-DNS name) and encode_ecs_option
// (ECS option) so the IP-parsing logic lives in exactly one place.
std::optional<ParsedAddr> parse_ip_addr(std::string_view addr) {
    if (addr.empty()) {
        return std::nullopt;
    }
    const std::string s(addr); // ldns requires a null-terminated C string
    std::unique_ptr<ldns_rdf, void (*)(ldns_rdf *)> rdf(
            ldns_rdf_new_frm_str(LDNS_RDF_TYPE_A, s.c_str()), &ldns_rdf_deep_free);
    if (rdf != nullptr) {
        ParsedAddr p{.family = 1, .len = 4};
        std::copy_n(ldns_rdf_data(rdf.get()), 4, p.bytes.begin());
        return p;
    }
    rdf.reset(ldns_rdf_new_frm_str(LDNS_RDF_TYPE_AAAA, s.c_str()));
    if (rdf != nullptr) {
        ParsedAddr p{.family = 2, .len = 16};
        std::copy_n(ldns_rdf_data(rdf.get()), 16, p.bytes.begin());
        return p;
    }
    return std::nullopt;
}

std::optional<std::string> make_reverse_name(std::string_view addr) {
    auto parsed = parse_ip_addr(addr);
    if (!parsed.has_value()) {
        return std::nullopt;
    }
    if (parsed->family == 1) {
        return fmt::format(
                "{}.{}.{}.{}.in-addr.arpa.", parsed->bytes[3], parsed->bytes[2], parsed->bytes[1], parsed->bytes[0]);
    }
    // IPv6: 16 address bytes -> 32 reversed nibbles, dot-separated.
    static constexpr char HEX[] = "0123456789abcdef";
    std::string out;
    out.reserve(2 * 32 + static_cast<size_t>(sizeof("ip6.arpa.")));
    for (int i = 15; i >= 0; --i) {
        uint8_t b = parsed->bytes[i];
        out += HEX[b & 0x0F];
        out += '.';
        out += HEX[(b >> 4) & 0x0F];
        out += '.';
    }
    out += "ip6.arpa.";
    return out;
}

std::vector<uint8_t> encode_ecs_option(std::string_view addr, uint8_t src_prefix) {
    auto parsed = parse_ip_addr(addr);
    if (!parsed.has_value()) {
        return {};
    }
    const uint8_t max_prefix = (parsed->family == 1) ? 32 : 128;
    if (src_prefix > max_prefix) {
        return {};
    }
    // option-data = family(2 BE) + source-prefix-len(1) + scope-prefix-len(1=0)
    //               + address (ceil(src_prefix/8) bytes, bits past the prefix
    //               in the last byte cleared).
    const size_t addr_len = static_cast<size_t>((src_prefix + 7) / 8);
    const uint8_t remainder = static_cast<uint8_t>(src_prefix % 8);
    std::vector<uint8_t> data;
    data.reserve(4 + addr_len);
    data.push_back(static_cast<uint8_t>((parsed->family >> 8) & 0xFF));
    data.push_back(static_cast<uint8_t>(parsed->family & 0xFF));
    data.push_back(src_prefix);
    data.push_back(0); // scope prefix-length (client->server: always 0)
    for (size_t i = 0; i < addr_len; ++i) {
        uint8_t b = parsed->bytes[i];
        if (i + 1 == addr_len && remainder != 0) {
            // Keep only the top `remainder` bits of the last address byte.
            b &= static_cast<uint8_t>(0xFF << (8 - remainder));
        }
        data.push_back(b);
    }
    // Full EDNS option TLV via the shared encoder (code 8 = Client Subnet,
    // RFC 7871); ldns stores these bytes verbatim as the OPT RR's RDATA.
    return encode_edns_option(0x08, data.data(), data.size());
}

std::vector<uint8_t> encode_edns_option(uint16_t code, const uint8_t *data, size_t len) {
    // option-code(2 BE) + option-length(2 BE) + option-data. This is exactly
    // the bytes ldns stores as the packet's EDNS data and writes verbatim as
    // the OPT RR's RDATA (LDNS_RDF_TYPE_NONE round-trips it untouched).
    std::vector<uint8_t> tlv;
    tlv.reserve(4 + len);
    tlv.push_back(static_cast<uint8_t>((code >> 8) & 0xFF));
    tlv.push_back(static_cast<uint8_t>(code & 0xFF));
    const uint16_t opt_len = static_cast<uint16_t>(len);
    tlv.push_back(static_cast<uint8_t>((opt_len >> 8) & 0xFF));
    tlv.push_back(static_cast<uint8_t>(opt_len & 0xFF));
    tlv.insert(tlv.end(), data, data + len);
    return tlv;
}

std::optional<uint16_t> parse_ednsopt_code(std::string_view code) {
    if (code.empty()) {
        return std::nullopt;
    }
    // Mnemonic -> option-code table, mirroring `dig`'s `optnames` (the dig
    // mnemonics a user may legitimately type at `+ednsopt=`). A mnemonic may
    // map to the same code as a longer one (e.g. PAD / PADDING -> 12); the
    // first exact case-insensitive match wins, exactly like dig's linear scan.
    struct Mnemonic {
        uint16_t code;
        std::string_view name;
    };
    static constexpr Mnemonic MNEMONICS[] = {
            {1, "LLQ"},
            {2, "UL"},
            {2, "UPDATE-LEASE"},
            {3, "NSID"},
            {5, "DAU"},
            {6, "DHU"},
            {7, "N3U"},
            {8, "ECS"},
            {9, "EXPIRE"},
            {10, "COOKIE"},
            {11, "KEEPALIVE"},
            {12, "PAD"},
            {12, "PADDING"},
            {13, "CHAIN"},
            {14, "KEY-TAG"},
            {15, "EDE"},
            {16, "CLIENT-TAG"},
            {17, "SERVER-TAG"},
            {18, "RC"},
            {18, "REPORT-CHANNEL"},
            {19, "ZONEVERSION"},
            {26946, "DEVICEID"},
    };
    auto ieq = [](std::string_view a, std::string_view b) {
        if (a.size() != b.size()) {
            return false;
        }
        for (size_t i = 0; i < a.size(); ++i) {
            if (std::toupper(static_cast<unsigned char>(a[i])) != std::toupper(static_cast<unsigned char>(b[i]))) {
                return false;
            }
        }
        return true;
    };
    for (const Mnemonic &m : MNEMONICS) {
        if (ieq(code, m.name)) {
            return m.code;
        }
    }
    // Decimal numeric code (dig uses parse_uint base 10, max 65535). 26946
    // (DEVICEID) fits in uint16_t, so it is reachable via the numeric form too
    // (e.g. `+ednsopt=26946`); the mnemonic is kept for dig compatibility.
    unsigned num = 0;
    const auto [ptr, ec] = std::from_chars(code.data(), code.data() + code.size(), num);
    if (ec == std::errc{} && ptr == code.data() + code.size() && num <= 65535) {
        return static_cast<uint16_t>(num);
    }
    return std::nullopt;
}

std::optional<std::vector<uint8_t>> decode_hex_string(std::string_view hex) {
    // Mirrors ISC's isc_hex_decodestring: ASCII whitespace is skipped, each
    // pair of hex digits yields a byte, and a stray (odd) digit or a non-hex
    // character is an error.
    auto hexval = [](unsigned char c) -> int {
        if (c >= '0' && c <= '9') {
            return c - '0';
        }
        if (c >= 'a' && c <= 'f') {
            return c - 'a' + 10;
        }
        if (c >= 'A' && c <= 'F') {
            return c - 'A' + 10;
        }
        return -1;
    };
    std::vector<uint8_t> out;
    int hi = -1; // pending high nibble, or -1 when none
    for (unsigned char c : hex) {
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
            continue;
        }
        int v = hexval(c);
        if (v < 0) {
            return std::nullopt;
        }
        if (hi < 0) {
            hi = v;
        } else {
            out.push_back(static_cast<uint8_t>((hi << 4) | v));
            hi = -1;
        }
    }
    if (hi >= 0) {
        return std::nullopt; // odd number of hex digits
    }
    return out;
}

// Render a CLIENT-SUBNET option-data address (family + raw bytes, zero-padded
// to the family's full width) the way ldns renders an A/AAA RDATA atom, so the
// displayed address matches adig's own RR rendering. Returns "<invalid>" on a
// malformed family/length combination.
static std::string format_ecs_address(uint16_t family, const uint8_t *bytes, size_t len) {
    ldns_rdf_type type = (family == 1) ? LDNS_RDF_TYPE_A : (family == 2) ? LDNS_RDF_TYPE_AAAA : LDNS_RDF_TYPE_NONE;
    if (type == LDNS_RDF_TYPE_NONE) {
        return "<invalid>";
    }
    // dig zero-pads the carried address to the full address length before
    // rendering, so e.g. /24 carries 3 bytes "01 02 03" -> "1.2.3.0".
    const size_t full = (family == 1) ? 4 : 16;
    std::array<uint8_t, 16> buf{};
    std::copy_n(bytes, std::min(len, full), buf.begin());
    ldns_rdf *rdf = ldns_rdf_new_frm_data(type, full, buf.data());
    if (rdf == nullptr) {
        return "<invalid>";
    }
    AllocatedPtr<char> s(ldns_rdf2str(rdf));
    ldns_rdf_deep_free(rdf);
    return (s != nullptr) ? std::string(s.get()) : "<invalid>";
}

// Copy raw option bytes into a std::string (byte-wise, via an integral
// static_cast) — avoids the `reinterpret_cast<const char *>` that the project's
// clang-tidy forbids (cppcoreguidelines-pro-type-reinterpret-cast).
static std::string bytes_to_string(const uint8_t *data, size_t len) {
    std::string s;
    s.reserve(len);
    for (size_t i = 0; i < len; ++i) {
        s += static_cast<char>(data[i]);
    }
    return s;
}

// Extended DNS Error (RFC 8914) info-code mnemonic. dig renders EDE as
// `; EDE: <code> (<MNEMONIC>)`; returns an empty string for an unknown code so
// the caller falls back to a numeric-only form.
static std::string_view ede_mnemonic(uint16_t code) {
    switch (code) {
    case 0:
        return "Other Error";
    case 1:
        return "Unsupported DNSKEY Algorithm";
    case 2:
        return "Unsupported DS Digest Type";
    case 3:
        return "Stale Answer";
    case 4:
        return "Forged Answer";
    case 5:
        return "DNSSEC Indeterminate";
    case 6:
        return "DNSSEC Bogus";
    case 7:
        return "Signature Expired";
    case 8:
        return "Signature Not Yet Valid";
    case 9:
        return "DNSKEY Missing";
    case 10:
        return "RRSIGs Missing";
    case 11:
        return "No Zone Key Bit Set";
    case 12:
        return "NSEC Missing";
    case 13:
        return "Cached Error";
    case 14:
        return "Not Ready";
    case 15:
        return "Blocked";
    case 16:
        return "Censored";
    case 17:
        return "Filtered";
    case 18:
        return "Prohibited";
    case 19:
        return "Stale NXDOMAIN Answer";
    case 20:
        return "Not Authoritative";
    case 21:
        return "Not Authorized";
    case 22:
        return "No Reachable Authority";
    case 23:
        return "Network Error";
    case 24:
        return "Invalid Data";
    case 25:
        return "Signature Expired before Valid";
    default:
        return {};
    }
}

std::string format_edns_option_text(uint16_t code, const uint8_t *data, size_t len) {
    // Each option is one dig `; <NAME>: <value>` line (terminated by '\n').
    if (code == 12) {
        // RFC 7830 Padding option. dig renders `; PADDING: (<N> bytes)`,
        // reflecting just the option-data length (the padding octets are all
        // zero by definition). Verified against `dig 9.20 +ednsopt=12`.
        return fmt::format("; PADDING: ({} bytes)\n", len);
    }
    if (code == 8 && len >= 4) {
        // CLIENT-SUBNET: family(2 BE), source-prefix-len(1), scope-prefix-len(1),
        // address(...). dig renders `; CLIENT-SUBNET: <addr>/<src>/<scope>`.
        uint16_t family = static_cast<uint16_t>((data[0] << 8) | data[1]);
        uint8_t src = data[2];
        uint8_t scope = data[3];
        std::string addr = format_ecs_address(family, data + 4, len - 4);
        return fmt::format("; CLIENT-SUBNET: {}/{}/{}\n", addr, src, scope);
    }
    if (code == 3) {
        // NSID (RFC 5001): the whole option-data is the server identity. dig
        // shows `; NSID: <hex> ("<ascii>")` (hex lower-case; in the quoted
        // string `"` and `\` are backslash-escaped and non-printables use the
        // \DDD octal form). When the option-data is empty dig prints just
        // `; NSID:` (no hex, no quoted string). Verified against `dig +nsid`
        // against a responder returning an empty NSID.
        if (len == 0) {
            return "; NSID:\n";
        }
        std::string hex;
        std::string ascii;
        // ASCII render of the NSID bytes in dig's quoted-string presentation
        // form. `"` (0x22) and `\` (0x5C) are otherwise printable, so the
        // escape check MUST run before the printable-range branch (otherwise
        // they are emitted raw and the escape is dead code).
        for (size_t i = 0; i < len; ++i) {
            hex += fmt::format("{:02x}", data[i]);
            unsigned char c = static_cast<unsigned char>(data[i]);
            if (c == '"' || c == '\\') {
                ascii += '\\';
                ascii += static_cast<char>(c);
            } else if (c >= 0x20 && c < 0x7f) {
                ascii += static_cast<char>(c);
            } else {
                ascii += fmt::format("\\{:03o}", c);
            }
        }
        return fmt::format("; NSID: {} (\"{}\")\n", hex, ascii);
    }
    if (code == 10 && len >= 8) {
        // COOKIE (RFC 7873): client cookie (8 bytes) + optional server cookie
        // (8..32 bytes). dig renders `; COOKIE: <client-hex>` for a client-only
        // cookie and `; COOKIE: <client-hex> (<server-hex>)` when a server
        // cookie follows. Verified against `dig 9.20` (its queries send an 8-byte
        // client cookie, rendered as `; COOKIE: <16 hex chars>`).
        std::string client_hex;
        for (size_t i = 0; i < 8; ++i) {
            client_hex += fmt::format("{:02x}", data[i]);
        }
        if (len > 8) {
            std::string server_hex;
            for (size_t i = 8; i < len; ++i) {
                server_hex += fmt::format("{:02x}", data[i]);
            }
            return fmt::format("; COOKIE: {} ({})\n", client_hex, server_hex);
        }
        return fmt::format("; COOKIE: {}\n", client_hex);
    }
    if (code == 15 && len >= 2) {
        // Extended DNS Error (RFC 8914): info-code(2 BE) + optional text.
        uint16_t infocode = static_cast<uint16_t>((data[0] << 8) | data[1]);
        std::string_view name = ede_mnemonic(infocode);
        if (!name.empty()) {
            if (len > 2) {
                return fmt::format("; EDE: {} ({}): {}\n", infocode, name, bytes_to_string(data + 2, len - 2));
            }
            return fmt::format("; EDE: {} ({})\n", infocode, name);
        }
        if (len > 2) {
            return fmt::format("; EDE: {}: {}\n", infocode, bytes_to_string(data + 2, len - 2));
        }
        return fmt::format("; EDE: {}\n", infocode);
    }
    // Unknown option: dig's generic `; \# <len> <hex>` form.
    std::string hex;
    for (size_t i = 0; i < len; ++i) {
        hex += fmt::format("{:02x}", data[i]);
    }
    return fmt::format("; \\# {} {}\n", len, hex);
}

std::optional<ldns_pkt_opcode> parse_opcode_name(std::string_view name) {
    if (name.empty()) {
        return std::nullopt;
    }
    // A raw numeric opcode (dig accepts `+opcode=4` as well as a name).
    unsigned num = 0;
    const auto [ptr, ec] = std::from_chars(name.data(), name.data() + name.size(), num);
    if (ec == std::errc{} && ptr == name.data() + name.size() && num <= 15) {
        return static_cast<ldns_pkt_opcode>(num);
    }
    // Case-insensitive name lookup (RFC 1035 opcodes; NOTIFY=RFC 1996, UPDATE=RFC 2136).
    auto ieq = [](std::string_view a, const char *b) {
        size_t n = 0;
        for (; n < a.size() && b[n] != '\0'; ++n) {
            if (std::toupper(static_cast<unsigned char>(a[n])) != static_cast<unsigned char>(b[n])) {
                return false;
            }
        }
        return n == a.size() && b[n] == '\0';
    };
    if (ieq(name, "QUERY")) {
        return LDNS_PACKET_QUERY;
    }
    if (ieq(name, "IQUERY")) {
        return LDNS_PACKET_IQUERY;
    }
    if (ieq(name, "STATUS")) {
        return LDNS_PACKET_STATUS;
    }
    if (ieq(name, "NOTIFY")) {
        return LDNS_PACKET_NOTIFY;
    }
    if (ieq(name, "UPDATE")) {
        return LDNS_PACKET_UPDATE;
    }
    return std::nullopt;
}

std::string format_dns_ttl_units(uint32_t ttl) {
    if (ttl == 0) {
        return "0";
    }
    // Each non-zero week/day/hour/minute/second unit is emitted in turn with
    // leading and trailing zero units suppressed (mirrors `dig 9.20`: 300 -> "5m",
    // 5400 -> "1h30m", 86400 -> "1d").
    struct Unit {
        uint32_t secs;
        char ch;
    };
    static constexpr Unit UNITS[] = {{604800, 'w'}, {86400, 'd'}, {3600, 'h'}, {60, 'm'}, {1, 's'}};
    std::string out;
    for (const Unit &u : UNITS) {
        uint32_t n = ttl / u.secs;
        if (n != 0) {
            out += fmt::format("{}{}", n, u.ch);
            ttl -= n * u.secs;
        }
    }
    return out;
}

std::string format_dns_ttl_verbose(uint32_t ttl) {
    // The verbose form used by dig's SOA multiline comments (`; refresh (2 hours
    // 46 minutes 40 seconds)`). Each non-zero week/day/hour/minute/second unit is
    // spelled out in full (singular when N==1, plural otherwise), space-separated,
    // with leading and trailing zero units suppressed. A zero TTL prints as
    // `0 seconds` (mirrors BIND's `dns_ttl_totext`, called by `soa_6.c` with
    // verbose=true for the refresh/retry/expire/minimum comments).
    if (ttl == 0) {
        return "0 seconds";
    }
    struct Unit {
        uint32_t secs;
        std::string_view singular;
        std::string_view plural;
    };
    static constexpr Unit UNITS[] = {
            {604800, "week", "weeks"},
            {86400, "day", "days"},
            {3600, "hour", "hours"},
            {60, "minute", "minutes"},
            {1, "second", "seconds"},
    };
    std::string out;
    bool first = true;
    uint32_t remaining = ttl;
    for (const Unit &u : UNITS) {
        uint32_t n = remaining / u.secs;
        remaining -= n * u.secs;
        if (n != 0) {
            if (!first) {
                out += ' ';
            }
            out += fmt::format("{} {}", n, n == 1 ? u.singular : u.plural);
            first = false;
        }
    }
    return out;
}

} // namespace ag::adig
