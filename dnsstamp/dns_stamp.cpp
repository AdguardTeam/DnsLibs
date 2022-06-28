#include <cassert>
#include <cstddef>
#include <cstring>
#include <event2/util.h>
#include <functional>
#include <initializer_list>
#include <list>
#include <type_traits>
#include <utility>
#include <vector>

#ifdef _WIN32
#include <ws2tcpip.h>
#endif

#include "common/base64.h"
#include "common/net_utils.h"
#include "common/net_consts.h"
#include "common/socket_address.h"
#include "common/utils.h"
#include "dnsstamp/dns_stamp.h"

namespace ag {

/// Function that writes stamp part
using WriteStampPartFunction = std::function<void(Uint8Vector &, const ServerStamp &)>;
/// Function that reads stamp part
using ReadStampPartFunction = std::function<ErrString(ServerStamp &, size_t &, const Uint8Vector &)>;

static constexpr auto PLAIN_STAMP_MIN_SIZE = 17;
static constexpr auto DNSCRYPT_STAMP_MIN_SIZE = 66;
static constexpr auto DOH_STAMP_MIN_SIZE = 19;
static constexpr auto DOT_STAMP_MIN_SIZE = 19;

static void write_bytes(Uint8Vector &result, const void *data, size_t size) {
    auto begin = static_cast<const uint8_t *>(data);
    auto end = begin + size;
    result.insert(result.end(), begin, end);
}

template <typename T>
static std::enable_if_t<std::is_standard_layout_v<T>> write_bytes(Uint8Vector &result, const T &value) {
    write_bytes(result, &value, sizeof value);
}

static void write_bytes_with_size(Uint8Vector &result, const void *data, size_t size, uint8_t mask = 0) {
    uint8_t size_data = size | mask;
    write_bytes(result, size_data);
    write_bytes(result, data, size);
}

template <typename T>
static decltype(std::declval<T>().data(), void(), std::declval<T>().size(), void()) // T has .data(), .size()
write_bytes_with_size(Uint8Vector &result, const T &value, uint8_t mask = 0) {
    write_bytes_with_size(result, value.data(), value.size(), mask);
}

static size_t read_size(size_t &pos, const Uint8Vector &value) {
    auto stamp_size = static_cast<size_t>(value[pos]);
    ++pos;
    return stamp_size;
}

static bool check_size(size_t size, size_t pos, const Uint8Vector &value) {
    return size + pos <= value.size();
}

static bool read_size_with_check(size_t &stamp_size, size_t &pos, const Uint8Vector &value) {
    stamp_size = read_size(pos, value);
    return check_size(stamp_size, pos, value);
}

template <typename T>
static bool read_bytes_using_size(T &result, size_t &pos, size_t stamp_size, const Uint8Vector &value) {
    result.reserve(stamp_size);
    auto begin = value.data() + pos;
    auto end = begin + stamp_size;
    result.insert(result.end(), begin, end);
    pos += stamp_size;
    return true;
}

template <typename T>
static bool read_bytes_with_size(T &result, size_t &pos, const Uint8Vector &value) {
    size_t stamp_size{};
    if (!read_size_with_check(stamp_size, pos, value)) {
        return false;
    }
    read_bytes_using_size(result, pos, stamp_size, value);
    return true;
}

template <typename T>
static void read_bytes(T &result, size_t &pos, const Uint8Vector &value) {
    memcpy(&result, value.data() + pos, sizeof result);
    pos += sizeof result;
}

static void write_stamp_proto_props_server_addr_str(
        Uint8Vector &bin, const ServerStamp &stamp, StampProtoType stamp_proto_type) {
    bin = {static_cast<uint8_t>(stamp_proto_type)};
    write_bytes(bin, stamp.props);
    write_bytes_with_size(bin, stamp.server_addr_str);
}

static void write_stamp_server_pk(Uint8Vector &bin, const ServerStamp &stamp) {
    write_bytes_with_size(bin, stamp.server_pk);
}

static void write_stamp_hashes(Uint8Vector &bin, const ServerStamp &stamp) {
    auto &hashes = stamp.hashes;
    if (hashes.empty()) {
        write_bytes(bin, uint8_t{0});
    } else {
        auto last_index = hashes.size() - 1;
        size_t i = 0;
        for (const auto &hash : hashes) {
            write_bytes_with_size(bin, hash, (i < last_index) ? 0x80 : 0);
            ++i;
        }
    }
}

static void write_stamp_provider_name(Uint8Vector &bin, const ServerStamp &stamp) {
    write_bytes_with_size(bin, stamp.provider_name);
}

static void write_stamp_path(Uint8Vector &bin, const ServerStamp &stamp) {
    write_bytes_with_size(bin, stamp.path);
}

static std::string stamp_string(
        const ServerStamp &stamp, StampProtoType stamp_proto_type, std::initializer_list<WriteStampPartFunction> fs) {
    Uint8Vector bin;
    write_stamp_proto_props_server_addr_str(bin, stamp, stamp_proto_type);
    for (const auto &f : fs) {
        f(bin, stamp);
    }
    return STAMP_URL_PREFIX_WITH_SCHEME + encode_to_base64(Uint8View(bin.data(), bin.size()), true);
}

static ErrString validate_server_addr_str(std::string_view addr_str) {
    auto [host, port, err] = utils::split_host_port_with_err(addr_str, true, true);
    if (err) {
        return ErrString(err);
    }
    if (!host.empty()) {
        SocketAddress addr(host, 0);
        if (!addr.valid()) {
            return ErrString("Invalid server address");
        }
    }
    if (!port.empty()) {
        std::string portStr{port};
        const char *ptr = portStr.data(), *end = portStr.data() + portStr.size();
        long portNumber = strtol(portStr.c_str(), (char **) &ptr, 10);
        if (ptr != end || portNumber <= 0 || portNumber > 65535) {
            return ErrString("Invalid server port");
        }
    }
    return std::nullopt;
}

static ErrString read_stamp_proto_props_server_addr_str(ServerStamp &stamp, size_t &pos, const Uint8Vector &value,
        StampProtoType proto, size_t min_value_size, uint16_t default_port) {
    stamp.proto = proto;
    if (value.size() < min_value_size) {
        return "Stamp is too short";
    }
    pos = 1;
    read_bytes(stamp.props, pos, value);
    if (!read_bytes_with_size(stamp.server_addr_str, pos, value)) {
        return "Invalid stamp";
    }
    return validate_server_addr_str(stamp.server_addr_str);
}

static ErrString read_stamp_server_pk(ServerStamp &stamp, size_t &pos, const Uint8Vector &value) {
    if (!read_bytes_with_size(stamp.server_pk, pos, value)) {
        return "Invalid stamp";
    }
    return std::nullopt;
}

static ErrString read_stamp_hashes(ServerStamp &stamp, size_t &pos, const Uint8Vector &value) {
    while (true) {
        uint8_t hash_size_raw = read_size(pos, value);
        uint8_t hash_size = hash_size_raw & ~0x80u;
        if (!check_size(hash_size, pos, value)) {
            return "Invalid stamp";
        }
        if (hash_size > 0) {
            stamp.hashes.emplace_back();
            read_bytes_using_size(stamp.hashes.back(), pos, hash_size, value);
        }
        if (!(hash_size_raw & 0x80u)) {
            break;
        }
    }
    return std::nullopt;
}

static ErrString read_stamp_provider_name(ServerStamp &stamp, size_t &pos, const Uint8Vector &value) {
    if (!read_bytes_with_size(stamp.provider_name, pos, value)) {
        return "Invalid stamp";
    }
    return std::nullopt;
}

static ErrString read_stamp_path(ServerStamp &stamp, size_t &pos, const Uint8Vector &value) {
    if (!read_bytes_with_size(stamp.path, pos, value)) {
        return "Invalid stamp";
    }
    return std::nullopt;
}

static ErrString check_garbage_after_end([[maybe_unused]] ServerStamp &stamp, size_t pos, const Uint8Vector &value) {
    if (pos != value.size()) {
        return "Invalid stamp (garbage after end)";
    }
    return std::nullopt;
}

static ServerStamp::FromStringResult new_server_stamp_basic(
        const Uint8Vector &bin, const std::list<ReadStampPartFunction> &fs) {
    ServerStamp result{};
    size_t pos{};
    for (const auto &f : fs) {
        if (auto error = f(result, pos, bin)) {
            return {std::move(result), std::move(error)};
        }
    }
    return {std::move(result), std::nullopt};
}

static ServerStamp::FromStringResult new_server_stamp(const Uint8Vector &bin, StampProtoType proto,
        size_t min_value_size, uint16_t port, std::list<ReadStampPartFunction> fs) {
    using namespace std::placeholders;
    fs.emplace_front([proto, min_value_size, port](ServerStamp &stamp, size_t &pos, const Uint8Vector &value) {
        return read_stamp_proto_props_server_addr_str(stamp, pos, value, proto, min_value_size, port);
    });
    fs.emplace_back(check_garbage_after_end);
    return new_server_stamp_basic(bin, fs);
}

static std::string stamp_plain_string(const ServerStamp &stamp) {
    return stamp_string(stamp, StampProtoType::PLAIN, {});
}

static std::string stamp_dnscrypt_string(const ServerStamp &stamp) {
    return stamp_string(stamp, StampProtoType::DNSCRYPT,
            {
                    write_stamp_server_pk,
                    write_stamp_provider_name,
            });
}

static std::string stamp_doh_string(const ServerStamp &stamp) {
    return stamp_string(stamp, StampProtoType::DOH,
            {
                    write_stamp_hashes,
                    write_stamp_provider_name,
                    write_stamp_path,
            });
}

static std::string stamp_dot_string(const ServerStamp &stamp) {
    return stamp_string(stamp, StampProtoType::TLS,
            {
                    write_stamp_hashes,
                    write_stamp_provider_name,
            });
}

static std::string stamp_doq_string(const ServerStamp &stamp) {
    return stamp_string(stamp, StampProtoType::DOQ,
            {
                    write_stamp_hashes,
                    write_stamp_provider_name,
            });
}

static ServerStamp::FromStringResult new_plain_server_stamp(const Uint8Vector &bin) {
    return new_server_stamp(bin, StampProtoType::PLAIN, PLAIN_STAMP_MIN_SIZE, ag::DEFAULT_PLAIN_PORT, {});
}

static ServerStamp::FromStringResult new_dnscrypt_server_stamp(const Uint8Vector &bin) {
    return new_server_stamp(bin, StampProtoType::DNSCRYPT, DNSCRYPT_STAMP_MIN_SIZE, ag::DEFAULT_DOH_PORT,
            {
                    read_stamp_server_pk,
                    read_stamp_provider_name,
            });
}

static ServerStamp::FromStringResult new_doh_server_stamp(const Uint8Vector &bin) {
    return new_server_stamp(bin, StampProtoType::DOH, DOH_STAMP_MIN_SIZE, ag::DEFAULT_DOH_PORT,
            {
                    read_stamp_hashes,
                    read_stamp_provider_name,
                    read_stamp_path,
            });
}

static ServerStamp::FromStringResult new_dot_server_stamp(const Uint8Vector &bin) {
    return new_server_stamp(bin, StampProtoType::TLS, DOT_STAMP_MIN_SIZE, ag::DEFAULT_DOT_PORT,
            {
                    read_stamp_hashes,
                    read_stamp_provider_name,
            });
}

static ServerStamp::FromStringResult new_doq_server_stamp(const Uint8Vector &bin) {
    return new_server_stamp(bin, StampProtoType::DOQ, DOT_STAMP_MIN_SIZE, ag::DEFAULT_DOQ_PORT,
            {
                    read_stamp_hashes,
                    read_stamp_provider_name,
            });
}

std::string ServerStamp::str() const {
    switch (proto) {
    case StampProtoType::PLAIN:
        return stamp_plain_string(*this);
    case StampProtoType::DNSCRYPT:
        return stamp_dnscrypt_string(*this);
    case StampProtoType::DOH:
        return stamp_doh_string(*this);
    case StampProtoType::TLS:
        return stamp_dot_string(*this);
    case StampProtoType::DOQ:
        return stamp_doq_string(*this);
    }
    assert(false);
    return {};
}

ServerStamp::FromStringResult ServerStamp::from_string(std::string_view url) {
    if (!utils::starts_with(url, STAMP_URL_PREFIX_WITH_SCHEME)) {
        return {{}, AG_FMT("Stamps are expected to start with {}", STAMP_URL_PREFIX_WITH_SCHEME)};
    }
    std::string_view encoded(url);
    encoded.remove_prefix(std::string_view(STAMP_URL_PREFIX_WITH_SCHEME).size());
    auto decoded_optional = decode_base64(encoded, true);
    if (!decoded_optional) {
        return {{}, "Invalid stamp"};
    }
    auto &decoded = *decoded_optional;
    if (decoded.empty()) {
        return {{}, "Stamp is too short"};
    }
    switch (StampProtoType{decoded[0]}) {
    case StampProtoType::PLAIN:
        return new_plain_server_stamp(decoded);
    case StampProtoType::DNSCRYPT:
        return new_dnscrypt_server_stamp(decoded);
    case StampProtoType::DOH:
        return new_doh_server_stamp(decoded);
    case StampProtoType::TLS:
        return new_dot_server_stamp(decoded);
    case StampProtoType::DOQ:
        return new_doq_server_stamp(decoded);
    default:
        return {{}, "Unsupported stamp version or protocol"};
    }
}

std::string ServerStamp::pretty_url(bool pretty_dnscrypt) const {
    if (proto == StampProtoType::DNSCRYPT) {
        if (!pretty_dnscrypt) {
            return str();
        }
        return AG_FMT("dnscrypt://{}", provider_name);
    }

    if (proto == StampProtoType::PLAIN) {
        auto [host, port] = ag::utils::split_host_port(server_addr_str);
        return port.empty() ? std::string{host} : server_addr_str;
    }

    std::string scheme;
    std::string default_port;

    switch (proto) {
    case StampProtoType::DOH:
        scheme = "https://";
        default_port = AG_FMT(":{}", DEFAULT_DOH_PORT);
        break;
    case StampProtoType::TLS:
        scheme = "tls://";
        default_port = AG_FMT(":{}", DEFAULT_DOT_PORT);
        break;
    case StampProtoType::DOQ:
        scheme = "quic://";
        default_port = AG_FMT(":{}", DEFAULT_DOQ_PORT);
        break;
    default:
        assert(0);
    }

    std::string port;
    if (!server_addr_str.empty()) {
        if (server_addr_str.front() == ':') {
            port = server_addr_str;
        } else {
            auto [host, port_view] = ag::utils::split_host_port(server_addr_str);
            if (!port_view.empty()) {
                port = AG_FMT(":{}", port_view);
            }
        }
    }

    return AG_FMT("{}{}{}{}", scheme, provider_name, port, path);
}

} // namespace ag
