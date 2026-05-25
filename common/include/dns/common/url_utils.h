#pragma once

#include <string>
#include <string_view>

namespace ag::dns {

/**
 * Mask the password in a URL string for safe logging.
 * E.g. "https://user:secret@host/path" -> "https://user:***@host/path"
 * If there is no password in the URL, returns the input unchanged.
 */
std::string mask_password(std::string_view url);

} // namespace ag::dns
