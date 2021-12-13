#pragma once

#include <optional>
#include <string>
#include <string_view>
#include <vector>
#include "common/defs.h"

namespace ag {

/**
 * Creates Base64-encoded string from data
 * @param data data to encode
 * @param url_safe is string should be url safe or not
 * @return Base64 encoded string
 */
std::string encode_to_base64(Uint8View data, bool url_safe);

/**
 * Decode data from Base64-encoded string
 * @param data Base64-encoded string
 * @param url_safe is string url safe or not
 * @return optional with bytes or null optional if string is not valid Base64-encoded
 */
std::optional<std::vector<uint8_t>> decode_base64(const std::string_view &data, bool url_safe);

} // namespace ag
