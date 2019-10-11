#include <cassert>
#include <cstddef>
#include <cstring>
#include <functional>
#include <initializer_list>
#include <list>
#include <type_traits>
#include <utility>
#include <vector>
#include <netdb.h>
#include <base64.h>
#include <dns_stamp.h>

namespace ag {

namespace {

using write_stamp_part_function_t = std::function<void(std::vector<std::byte> &, const server_stamp &)>;
using read_stamp_part_function_t = std::function<std::string(server_stamp &, size_t &, const std::vector<std::byte> &)>;

constexpr auto PLAIN_STAMP_MIN_SIZE = 17;
constexpr auto DNSCRYPT_STAMP_MIN_SIZE = 66;
constexpr auto DOH_STAMP_MIN_SIZE = 22;
constexpr auto DOT_STAMP_MIN_SIZE = 22;

// TODO use starts_with since C++20
bool starts_with(std::string_view sv, std::string_view sub_sv) {
    return sv.size() >= sub_sv.size() && sv.compare(0, sub_sv.size(), sub_sv) == 0;
}

// TODO use ends_with since C++20
bool ends_with(std::string_view sv, std::string_view sub_sv) {
    return sv.size() >= sub_sv.size() &&
           sv.compare(sv.size() - sub_sv.size(), std::string_view::npos, sub_sv) == 0;
}

std::string_view remove_suffix_if_exists(std::string_view value, std::string_view suffix) {
    auto suffix_size = (ends_with(value, suffix)) ? suffix.size() : 0;
    std::string_view result(value);
    result.remove_suffix(suffix_size);
    return result;
}

void write_bytes(std::vector<std::byte> &result, const void *data, size_t size) {
    auto begin = static_cast<const std::byte *>(data);
    auto end = begin + size;
    result.insert(result.end(), begin, end);
}

template<typename T>
std::enable_if_t<std::is_pod_v<T>>
write_bytes(std::vector<std::byte> &result, const T &value) {
    write_bytes(result, &value, sizeof value);
}

void write_bytes_with_size(std::vector<std::byte> &result, const void *data, size_t size, uint8_t mask = 0) {
    uint8_t size_data = size | mask;
    write_bytes(result, size_data);
    write_bytes(result, data, size);
}

template<typename T>
decltype(std::declval<T>().data(), void(), std::declval<T>().size(), void())
write_bytes_with_size(std::vector<std::byte> &result, const T &value, uint8_t mask = 0) {
    write_bytes_with_size(result, value.data(), value.size(), mask);
}

size_t read_size(size_t &pos, const std::vector<std::byte> &value) {
    auto stamp_size = static_cast<size_t>(value[pos]);
    ++pos;
    return stamp_size;
}

bool check_size(size_t size, size_t pos, const std::vector<std::byte> &value) {
    return size + pos <= value.size();
}

bool read_size_with_check(size_t &stamp_size, size_t &pos, const std::vector<std::byte> &value) {
    stamp_size = read_size(pos, value);
    return check_size(stamp_size, pos, value);
}

template<typename T>
bool read_bytes_using_size(T &result, size_t &pos, size_t stamp_size, const std::vector<std::byte> &value) {
    result.reserve(stamp_size);
    auto begin = reinterpret_cast<const typename T::value_type *>(value.data()) + pos;
    auto end = begin + stamp_size;
    result.insert(result.end(), begin, end);
    pos += stamp_size;
    return true;
}

template<typename T>
bool read_bytes_with_size(T &result, size_t &pos, const std::vector<std::byte> &value) {
    size_t stamp_size{};
    if (!read_size_with_check(stamp_size, pos, value)) {
        return false;
    }
    read_bytes_using_size(result, pos, stamp_size, value);
    return true;
}

template<typename T>
void read_bytes(T &result, size_t &pos, const std::vector<std::byte> &value) {
    memcpy(&result, value.data() + pos, sizeof result);
    pos += sizeof result;
}

void write_stamp_proto_props_server_addr_str(std::vector<std::byte> &bin, const server_stamp &stamp,
                                             stamp_proto_type stamp_proto_type, stamp_port_t port) {
    using namespace std::string_literals;
    bin = {static_cast<std::byte>(stamp_proto_type)};
    write_bytes(bin, stamp.props);
    auto port_suffix = ":"s + std::to_string(port); // TODO use std::to_chars when Apple Clang will have it
    write_bytes_with_size(bin, remove_suffix_if_exists(stamp.server_addr_str, port_suffix));
}

void write_stamp_server_pk(std::vector<std::byte> &bin, const server_stamp &stamp) {
    write_bytes_with_size(bin, stamp.server_pk);
}

void write_stamp_hashes(std::vector<std::byte> &bin, const server_stamp &stamp) {
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

void write_stamp_provider_name(std::vector<std::byte> &bin, const server_stamp &stamp) {
    write_bytes_with_size(bin, stamp.provider_name);
}

void write_stamp_path(std::vector<std::byte> &bin, const server_stamp &stamp) {
    write_bytes_with_size(bin, stamp.path);
}

std::string stamp_string(const server_stamp &stamp, stamp_proto_type stamp_proto_type, stamp_port_t port,
                         std::initializer_list<write_stamp_part_function_t> fs) {
    std::vector<std::byte> bin;
    write_stamp_proto_props_server_addr_str(bin, stamp, stamp_proto_type, port);
    for (const auto &f : fs) {
        f(bin, stamp);
    }
    return STAMP_URL_PREFIX_WITH_SCHEME + encode_to_base64(bytes_view_t(bin.data(), bin.size()), true);
}

std::string read_stamp_proto_props_server_addr_str(server_stamp &stamp, size_t &pos,
                                                   const std::vector<std::byte> &value, stamp_proto_type proto,
                                                   size_t min_value_size, stamp_port_t port) {
    using namespace std::string_literals;
    stamp.proto = proto;
    if (value.size() < min_value_size) {
        return "stamp is too short";
    }
    pos = 1;
    read_bytes(stamp.props, pos, value);
    if (!read_bytes_with_size(stamp.server_addr_str, pos, value)) {
        return "invalid stamp";
    }
    std::string_view addr_str_copy_sv = stamp.server_addr_str;
    if (auto starts_with_bracket = addr_str_copy_sv.front() == '[', ends_with_bracket = addr_str_copy_sv.back() == ']';
        starts_with_bracket && ends_with_bracket) {
        addr_str_copy_sv = addr_str_copy_sv.substr(1, addr_str_copy_sv.size() - 2);
    } else if (starts_with_bracket || ends_with_bracket) {
        return "invalid stamp";
    }
    addrinfo* addrinfo_res = nullptr;
    addrinfo addrinfo_hints{};
    addrinfo_hints.ai_family = AF_UNSPEC;
    addrinfo_hints.ai_flags = AI_NUMERICHOST;
    std::string addr_str_copy_s(addr_str_copy_sv.begin(), addr_str_copy_sv.end());
    auto getaddrinfo_result = getaddrinfo(addr_str_copy_s.c_str(), nullptr, &addrinfo_hints, &addrinfo_res);
    if (getaddrinfo_result == 0 && (addrinfo_res->ai_family == AF_INET || addrinfo_res->ai_family == AF_INET6)) {
        stamp.server_addr_str += ":"s + std::to_string(port);
    }
    return {};
}

std::string read_stamp_server_pk(server_stamp &stamp, size_t &pos, const std::vector<std::byte> &value) {
    if (!read_bytes_with_size(stamp.server_pk, pos, value)) {
        return "invalid stamp";
    }
    return {};
}

std::string read_stamp_hashes(server_stamp &stamp, size_t &pos, const std::vector<std::byte> &value) {
    while (true) {
        uint8_t hash_size = read_size(pos, value) & ~0x80u;
        if (!check_size(hash_size, pos, value)) {
            return "invalid stamp";
        }
        if (hash_size > 0) {
            stamp.hashes.emplace_back();
            read_bytes_using_size(stamp.hashes.back(), pos, hash_size, value);
        }
        if (!(hash_size & 0x80u)) {
            break;
        }
    }
    return {};
}

std::string read_stamp_provider_name(server_stamp &stamp, size_t &pos, const std::vector<std::byte> &value) {
    if (!read_bytes_with_size(stamp.provider_name, pos, value)) {
        return "invalid stamp";
    }
    return {};
}

std::string read_stamp_path(server_stamp &stamp, size_t &pos, const std::vector<std::byte> &value) {
    if (!read_bytes_with_size(stamp.path, pos, value)) {
        return "invalid stamp";
    }
    return {};
}

std::string check_garbage_after_end([[maybe_unused]] server_stamp &stamp, size_t pos,
                                    const std::vector<std::byte> &value) {
    if (pos != value.size()) {
        return "invalid stamp (garbage after end)";
    }
    return {};
}

std::pair<server_stamp, std::string> new_server_stamp_basic(const std::vector<std::byte> &bin,
                                                            const std::list<read_stamp_part_function_t> &fs) {
    server_stamp result{};
    size_t pos{};
    for (const auto &f : fs) {
        if (auto error = f(result, pos, bin); !error.empty()) {
            return {std::move(result), error};
        }
    }
    return {std::move(result), std::string{}};
}

std::pair<server_stamp, std::string> new_server_stamp(const std::vector<std::byte> &bin, stamp_proto_type proto,
                                                      size_t min_value_size, stamp_port_t port,
                                                      std::list<read_stamp_part_function_t> fs) {
    using namespace std::placeholders;
    fs.emplace_front(std::bind(read_stamp_proto_props_server_addr_str, _1, _2, _3, proto, min_value_size, port));
    fs.emplace_back(check_garbage_after_end);
    return new_server_stamp_basic(bin, fs);
}

std::string stamp_plain_string(const server_stamp &stamp) {
    return stamp_string(stamp, stamp_proto_type::PLAIN, DEFAULT_PLAIN_PORT, {});
}

std::string stamp_dnscrypt_string(const server_stamp &stamp) {
    return stamp_string(stamp, stamp_proto_type::DNSCRYPT, DEFAULT_DOH_PORT, {
        write_stamp_server_pk,
        write_stamp_provider_name,
    });
}

std::string stamp_doh_string(const server_stamp &stamp) {
    return stamp_string(stamp, stamp_proto_type::DOH, DEFAULT_DOH_PORT, {
        write_stamp_hashes,
        write_stamp_provider_name,
        write_stamp_path,
    });
}

std::string stamp_dot_string(const server_stamp &stamp) {
    return stamp_string(stamp, stamp_proto_type::TLS, DEFAULT_DOT_PORT, {
        write_stamp_hashes,
        write_stamp_provider_name,
    });
}

std::pair<server_stamp, std::string> new_plain_server_stamp(const std::vector<std::byte> &bin) {
    return new_server_stamp(bin, stamp_proto_type::PLAIN, PLAIN_STAMP_MIN_SIZE, DEFAULT_PLAIN_PORT, {});
}

std::pair<server_stamp, std::string> new_dnscrypt_server_stamp(const std::vector<std::byte> &bin) {
    return new_server_stamp(bin, stamp_proto_type::DNSCRYPT, DNSCRYPT_STAMP_MIN_SIZE, DEFAULT_DOH_PORT, {
        read_stamp_server_pk,
        read_stamp_provider_name,
    });
}

std::pair<server_stamp, std::string> new_doh_server_stamp(const std::vector<std::byte> &bin) {
    return new_server_stamp(bin, stamp_proto_type::DOH, DOH_STAMP_MIN_SIZE, DEFAULT_DOH_PORT, {
        read_stamp_hashes,
        read_stamp_provider_name,
        read_stamp_path,
    });
}

std::pair<server_stamp, std::string> new_dot_server_stamp(const std::vector<std::byte> &bin) {
    return new_server_stamp(bin, stamp_proto_type::TLS, DOT_STAMP_MIN_SIZE, DEFAULT_DOT_PORT, {
        read_stamp_hashes,
        read_stamp_provider_name,
    });
}

} // namespace

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
        default:
            assert(false);
            return {};
    }
}

std::pair<server_stamp, std::string> server_stamp::from_string(std::string_view url) {
    using namespace std::string_literals;
    if (!starts_with(url, STAMP_URL_PREFIX_WITH_SCHEME)) {
        return {{}, "stamps are expected to start with "s + STAMP_URL_PREFIX_WITH_SCHEME};
    }
    std::string_view encoded(url);
    encoded.remove_prefix(std::string_view(STAMP_URL_PREFIX_WITH_SCHEME).size());
    auto decoded_optional = decode_base64(encoded, true);
    if (!decoded_optional) {
        return {{}, "invalid stamp"};
    }
    auto &decoded = *decoded_optional;
    if (decoded.empty()) {
        return {{}, "stamp is too short"};
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
        default:
            return {{}, "unsupported stamp version or protocol"};
    }
}

} // namespace ag
