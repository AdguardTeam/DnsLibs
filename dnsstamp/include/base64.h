#ifndef AGDNS_DNSSTAMP_BASE64_H
#define AGDNS_DNSSTAMP_BASE64_H

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace ag {

using bytes_view_t = std::basic_string_view<std::byte>;

/**
 * Creates Base64-encoded string from data
 * @param data data to encode
 * @param url_safe is string should be url safe or not
 * @return Base64 encoded string
 */
std::string encode_to_base64(bytes_view_t data, bool url_safe);

/**
 * Decode data from Base64-encoded string
 * @param data Base64-encoded string
 * @param url_safe is string url safe or not
 * @return optional with bytes or null optional if string is not valid Base64-encoded
 */
std::optional<std::vector<std::byte>> decode_base64(const std::string_view &data, bool url_safe);

} // namespace ag

#endif // AGDNS_DNSSTAMP_BASE64_H
