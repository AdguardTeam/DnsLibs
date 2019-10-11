#include <cstdint>
#include <array>
#include <vector>
#include <base64.h>

namespace ag {

namespace {

using base64_table_t = std::array<uint8_t, 65>;
using basis_t = std::array<uint8_t, 256>;

constexpr auto url_safe_base64_table(const base64_table_t &xs) noexcept {
    auto result = xs;
    for (auto &x: result) {
        switch (x) {
            case '+':
                x = '-';
                continue;
            case '/':
                x = '_';
                continue;
            default:
                continue;
        }
    }
    return result;
}

constexpr auto url_safe_basis(const basis_t &xs) noexcept {
    // TODO use constexpr std::swap since C++20
    auto constexpr_swap = [](auto &a, auto &b) {
        auto t = a;
        a = b;
        b = t;
    };
    auto result = xs;
    constexpr_swap(result['-'], result['+']);
    constexpr_swap(result['_'], result['/']);
    return result;
}

constexpr size_t encode_base64_size(size_t len) noexcept {
    return (len + 2) / 3 * 4;
}

constexpr size_t decode_base64_size(size_t len) noexcept {
    return (len + 3) / 4 * 3;
}

constexpr base64_table_t BASE64_TABLE_DEFAULT{"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"};
constexpr auto BASE64_TABLE_URL_SAFE = url_safe_base64_table(BASE64_TABLE_DEFAULT);
constexpr basis_t BASIS_DEFAULT{
    77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
    77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
    77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 62, 77, 77, 77, 63,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 77, 77, 77, 77, 77, 77,
    77,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 77, 77, 77, 77, 77,
    77, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 77, 77, 77, 77, 77,

    77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
    77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
    77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
    77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
    77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
    77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
    77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
    77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
};
constexpr auto BASIS_URL_SAFE = url_safe_basis(BASIS_DEFAULT);
constexpr auto PADDING = '=';

} // namespace

std::string encode_to_base64(bytes_view_t data, bool url_safe)
{
    const auto base64_table = url_safe ? BASE64_TABLE_URL_SAFE : BASE64_TABLE_DEFAULT;
    auto in_pos = reinterpret_cast<const uint8_t *>(data.data());
    auto end = reinterpret_cast<const uint8_t *>(data.data() + data.size());
    std::string result;
    result.reserve(encode_base64_size(data.size()));
    while (in_pos + 2 < end) {
        result.push_back(base64_table[in_pos[0] >> 2]);
        result.push_back(base64_table[((in_pos[0] & 0x03) << 4) | (in_pos[1] >> 4)]);
        result.push_back(base64_table[((in_pos[1] & 0x0f) << 2) | (in_pos[2] >> 6)]);
        result.push_back(base64_table[in_pos[2] & 0x3f]);
        in_pos += 3;
    }
    if (in_pos < end) {
        result.push_back(base64_table[in_pos[0] >> 2]);
        if (end - in_pos == 1) {
            result.push_back(base64_table[(in_pos[0] & 0x03) << 4]);
            if (!url_safe) {
                result.push_back(PADDING);
            }
        } else {
            result.push_back(base64_table[((in_pos[0] & 0x03) << 4) | (in_pos[1] >> 4)]);
            result.push_back(base64_table[(in_pos[1] & 0x0f) << 2]);
        }
        if (!url_safe) {
            result.push_back(PADDING);
        }
    }
    return result;
}

std::optional<std::vector<std::byte>> decode_base64(const std::string_view &data, bool url_safe)
{
    const auto &basis = url_safe ? BASIS_URL_SAFE : BASIS_DEFAULT;
    auto src = reinterpret_cast<const uint8_t *>(data.data());
    auto src_len = data.size();
    size_t len;
    for (len = 0; len < src_len; len++) {
        if (src[len] == PADDING) {
            break;
        }
        if (basis[src[len]] == 77) {
            return std::nullopt;
        }
    }
    if (len % 4 == 1) {
        return std::nullopt;
    }
    std::vector<std::byte> result;
    result.reserve(decode_base64_size(src_len));
    auto s = src;
    while (len > 3) {
        result.emplace_back(static_cast<std::byte>(basis[s[0]] << 2 | basis[s[1]] >> 4));
        result.emplace_back(static_cast<std::byte>(basis[s[1]] << 4 | basis[s[2]] >> 2));
        result.emplace_back(static_cast<std::byte>(basis[s[2]] << 6 | basis[s[3]]));
        s += 4;
        len -= 4;
    }
    if (len > 1) {
        result.emplace_back(static_cast<std::byte>(basis[s[0]] << 2 | basis[s[1]] >> 4));
    }
    if (len > 2) {
        result.emplace_back(static_cast<std::byte>(basis[s[1]] << 4 | basis[s[2]] >> 2));
    }
    return result;
}

} // namespace ag
