#include <cassert>
#include <cstddef>
#include <cstring>
#include <functional>
#include <initializer_list>
#include <list>
#include <type_traits>
#include <utility>
#include <vector>
#include <event2/util.h>
#include <ag_utils.h>
#include <ag_net_utils.h>
#include <ag_socket_address.h>
#include <base64.h>
#include <dns_stamp.h>
#ifdef _WIN32
#include <ws2tcpip.h>
#endif

namespace ag {

using write_stamp_part_function_t = std::function<void(std::vector<uint8_t> &, const server_stamp &)>;
using read_stamp_part_function_t = std::function<err_string(server_stamp &, size_t &, const std::vector<uint8_t> &)>;

static constexpr auto PLAIN_STAMP_MIN_SIZE = 17;
static constexpr auto DNSCRYPT_STAMP_MIN_SIZE = 66;
static constexpr auto DOH_STAMP_MIN_SIZE = 19;
static constexpr auto DOT_STAMP_MIN_SIZE = 19;

static void write_bytes(std::vector<uint8_t> &result, const void *data, size_t size) {
    auto begin = static_cast<const uint8_t *>(data);
    auto end = begin + size;
    result.insert(result.end(), begin, end);
}

template<typename T>
static std::enable_if_t<std::is_standard_layout_v<T>>
write_bytes(std::vector<uint8_t> &result, const T &value) {
    write_bytes(result, &value, sizeof value);
}

static void write_bytes_with_size(std::vector<uint8_t> &result, const void *data, size_t size, uint8_t mask = 0) {
    uint8_t size_data = size | mask;
    write_bytes(result, size_data);
    write_bytes(result, data, size);
}

template<typename T>
static decltype(std::declval<T>().data(), void(), std::declval<T>().size(), void()) // T has .data(), .size()
write_bytes_with_size(std::vector<uint8_t> &result, const T &value, uint8_t mask = 0) {
    write_bytes_with_size(result, value.data(), value.size(), mask);
}

static size_t read_size(size_t &pos, const std::vector<uint8_t> &value) {
    auto stamp_size = static_cast<size_t>(value[pos]);
    ++pos;
    return stamp_size;
}

static bool check_size(size_t size, size_t pos, const std::vector<uint8_t> &value) {
    return size + pos <= value.size();
}

static bool read_size_with_check(size_t &stamp_size, size_t &pos, const std::vector<uint8_t> &value) {
    stamp_size = read_size(pos, value);
    return check_size(stamp_size, pos, value);
}

template<typename T>
static bool read_bytes_using_size(T &result, size_t &pos, size_t stamp_size, const std::vector<uint8_t> &value) {
    result.reserve(stamp_size);
    auto begin = value.data() + pos;
    auto end = begin + stamp_size;
    result.insert(result.end(), begin, end);
    pos += stamp_size;
    return true;
}

template<typename T>
static bool read_bytes_with_size(T &result, size_t &pos, const std::vector<uint8_t> &value) {
    size_t stamp_size{};
    if (!read_size_with_check(stamp_size, pos, value)) {
        return false;
    }
    read_bytes_using_size(result, pos, stamp_size, value);
    return true;
}

template<typename T>
static void read_bytes(T &result, size_t &pos, const std::vector<uint8_t> &value) {
    memcpy(&result, value.data() + pos, sizeof result);
    pos += sizeof result;
}

static void write_stamp_proto_props_server_addr_str(std::vector<uint8_t> &bin, const server_stamp &stamp,
                                                    stamp_proto_type stamp_proto_type) {
    bin = {static_cast<uint8_t>(stamp_proto_type)};
    write_bytes(bin, stamp.props);
    write_bytes_with_size(bin, stamp.server_addr_str);
}

static void write_stamp_server_pk(std::vector<uint8_t> &bin, const server_stamp &stamp) {
    write_bytes_with_size(bin, stamp.server_pk);
}

static void write_stamp_hashes(std::vector<uint8_t> &bin, const server_stamp &stamp) {
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

static void write_stamp_provider_name(std::vector<uint8_t> &bin, const server_stamp &stamp) {
    write_bytes_with_size(bin, stamp.provider_name);
}

static void write_stamp_path(std::vector<uint8_t> &bin, const server_stamp &stamp) {
    write_bytes_with_size(bin, stamp.path);
}

static std::string stamp_string(const server_stamp &stamp, stamp_proto_type stamp_proto_type,
                                std::initializer_list<write_stamp_part_function_t> fs) {
    std::vector<uint8_t> bin;
    write_stamp_proto_props_server_addr_str(bin, stamp, stamp_proto_type);
    for (const auto &f : fs) {
        f(bin, stamp);
    }
    return STAMP_URL_PREFIX_WITH_SCHEME + encode_to_base64(uint8_view(bin.data(), bin.size()), true);
}

static err_string validate_server_addr_str(std::string_view addr_str) {
    auto[host, port, err] = utils::split_host_port_with_err(addr_str, true, true);
    if (err) {
        return err_string(err);
    }
    if (!host.empty()) {
        socket_address addr(host, 0);
        if (!addr.valid()) {
            return err_string("Invalid server address");
        }
    }
    if (!port.empty()) {
        std::string portStr{port};
        const char *ptr = portStr.data(), *end = portStr.data() + portStr.size();
        long portNumber = strtol(portStr.c_str(), (char **)&ptr, 10);
        if (ptr != end || portNumber <= 0 || portNumber > 65535) {
            return err_string("Invalid server port");
        }
    }
    return std::nullopt;
}

static err_string read_stamp_proto_props_server_addr_str(server_stamp &stamp, size_t &pos,
                                                         const std::vector<uint8_t> &value, stamp_proto_type proto,
                                                         size_t min_value_size, stamp_port default_port) {
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

static err_string read_stamp_server_pk(server_stamp &stamp, size_t &pos, const std::vector<uint8_t> &value) {
    if (!read_bytes_with_size(stamp.server_pk, pos, value)) {
        return "Invalid stamp";
    }
    return std::nullopt;
}

static err_string read_stamp_hashes(server_stamp &stamp, size_t &pos, const std::vector<uint8_t> &value) {
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

static err_string read_stamp_provider_name(server_stamp &stamp, size_t &pos, const std::vector<uint8_t> &value) {
    if (!read_bytes_with_size(stamp.provider_name, pos, value)) {
        return "Invalid stamp";
    }
    return std::nullopt;
}

static err_string read_stamp_path(server_stamp &stamp, size_t &pos, const std::vector<uint8_t> &value) {
    if (!read_bytes_with_size(stamp.path, pos, value)) {
        return "Invalid stamp";
    }
    return std::nullopt;
}

static err_string check_garbage_after_end([[maybe_unused]] server_stamp &stamp, size_t pos,
                                          const std::vector<uint8_t> &value) {
    if (pos != value.size()) {
        return "Invalid stamp (garbage after end)";
    }
    return std::nullopt;
}

static server_stamp::from_str_result new_server_stamp_basic(const std::vector<uint8_t> &bin,
                                                     const std::list<read_stamp_part_function_t> &fs) {
    server_stamp result{};
    size_t pos{};
    for (const auto &f : fs) {
        if (auto error = f(result, pos, bin)) {
            return {std::move(result), std::move(error)};
        }
    }
    return {std::move(result), std::nullopt};
}

static server_stamp::from_str_result new_server_stamp(const std::vector<uint8_t> &bin, stamp_proto_type proto,
                                                      size_t min_value_size, stamp_port port,
                                                      std::list<read_stamp_part_function_t> fs) {
    using namespace std::placeholders;
    fs.emplace_front(std::bind(read_stamp_proto_props_server_addr_str, _1, _2, _3, proto, min_value_size, port));
    fs.emplace_back(check_garbage_after_end);
    return new_server_stamp_basic(bin, fs);
}

static std::string stamp_plain_string(const server_stamp &stamp) {
    return stamp_string(stamp, stamp_proto_type::PLAIN, {});
}

static std::string stamp_dnscrypt_string(const server_stamp &stamp) {
    return stamp_string(stamp, stamp_proto_type::DNSCRYPT, {
            write_stamp_server_pk,
            write_stamp_provider_name,
    });
}

static std::string stamp_doh_string(const server_stamp &stamp) {
    return stamp_string(stamp, stamp_proto_type::DOH, {
            write_stamp_hashes,
            write_stamp_provider_name,
            write_stamp_path,
    });
}

static std::string stamp_dot_string(const server_stamp &stamp) {
    return stamp_string(stamp, stamp_proto_type::TLS, {
            write_stamp_hashes,
            write_stamp_provider_name,
    });
}

static std::string stamp_doq_string(const server_stamp &stamp) {
    return stamp_string(stamp, stamp_proto_type::DOQ, {
            write_stamp_hashes,
            write_stamp_provider_name,
    });
}

static server_stamp::from_str_result new_plain_server_stamp(const std::vector<uint8_t> &bin) {
    return new_server_stamp(bin, stamp_proto_type::PLAIN, PLAIN_STAMP_MIN_SIZE, DEFAULT_PLAIN_PORT, {});
}

static server_stamp::from_str_result new_dnscrypt_server_stamp(const std::vector<uint8_t> &bin) {
    return new_server_stamp(bin, stamp_proto_type::DNSCRYPT, DNSCRYPT_STAMP_MIN_SIZE, DEFAULT_DOH_PORT, {
        read_stamp_server_pk,
        read_stamp_provider_name,
    });
}

static server_stamp::from_str_result new_doh_server_stamp(const std::vector<uint8_t> &bin) {
    return new_server_stamp(bin, stamp_proto_type::DOH, DOH_STAMP_MIN_SIZE, DEFAULT_DOH_PORT, {
        read_stamp_hashes,
        read_stamp_provider_name,
        read_stamp_path,
    });
}

static server_stamp::from_str_result new_dot_server_stamp(const std::vector<uint8_t> &bin) {
    return new_server_stamp(bin, stamp_proto_type::TLS, DOT_STAMP_MIN_SIZE, DEFAULT_DOT_PORT, {
        read_stamp_hashes,
        read_stamp_provider_name,
    });
}

static server_stamp::from_str_result new_doq_server_stamp(const std::vector<uint8_t> &bin) {
    return new_server_stamp(bin, stamp_proto_type::DOQ, DOT_STAMP_MIN_SIZE, DEFAULT_DOQ_PORT, {
            read_stamp_hashes,
            read_stamp_provider_name,
    });
}

std::string server_stamp::str() const {
    switch (proto) {
    case stamp_proto_type::PLAIN:
        return stamp_plain_string(*this);
    case stamp_proto_type::DNSCRYPT:
        return stamp_dnscrypt_string(*this);
    case stamp_proto_type::DOH:
        return stamp_doh_string(*this);
    case stamp_proto_type::TLS:
        return stamp_dot_string(*this);
    case stamp_proto_type::DOQ:
        return stamp_doq_string(*this);
    }
    assert(false);
    return {};
}

server_stamp::from_str_result server_stamp::from_string(std::string_view url) {
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
    switch (stamp_proto_type{decoded[0]}) {
    case stamp_proto_type::PLAIN:
        return new_plain_server_stamp(decoded);
    case stamp_proto_type::DNSCRYPT:
        return new_dnscrypt_server_stamp(decoded);
    case stamp_proto_type::DOH:
        return new_doh_server_stamp(decoded);
    case stamp_proto_type::TLS:
        return new_dot_server_stamp(decoded);
    case stamp_proto_type::DOQ:
        return new_doq_server_stamp(decoded);
    default:
        return {{}, "Unsupported stamp version or protocol"};
    }
}

std::string server_stamp::pretty_url(bool pretty_dnscrypt) const {
    if (proto == stamp_proto_type::DNSCRYPT) {
        if (!pretty_dnscrypt) {
            return str();
        }
        return AG_FMT("dnscrypt://{}", provider_name);
    }

    if (proto == stamp_proto_type::PLAIN) {
        auto[host, port] = ag::utils::split_host_port(server_addr_str);
        return port.empty() ? std::string{host} : server_addr_str;
    }

    std::string scheme;
    std::string default_port;

    switch (proto) {
    case stamp_proto_type::DOH:
        scheme = "https://";
        default_port = AG_FMT(":{}", DEFAULT_DOH_PORT);
        break;
    case stamp_proto_type::TLS:
        scheme = "tls://";
        default_port = AG_FMT(":{}", DEFAULT_DOT_PORT);
        break;
    case stamp_proto_type::DOQ:
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
            auto[host, port_view] = ag::utils::split_host_port(server_addr_str);
            if (!port_view.empty()) {
                port = AG_FMT(":{}", port_view);
            }
        }
    }

    return AG_FMT("{}{}{}{}", scheme, provider_name, port, path);
}

} // namespace ag
