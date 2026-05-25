#include "dns/common/url_utils.h"

namespace ag::dns {

std::string mask_password(std::string_view url) {
    auto scheme_end = url.find("://");
    if (scheme_end == std::string_view::npos) {
        return std::string(url);
    }
    auto authority_start = scheme_end + 3;
    auto at_pos = url.find('@', authority_start);
    if (at_pos == std::string_view::npos) {
        return std::string(url);
    }
    // Ensure '@' is in the authority part (before path '/')
    auto slash_pos = url.find('/', authority_start);
    if (slash_pos != std::string_view::npos && at_pos > slash_pos) {
        return std::string(url);
    }
    auto userinfo = url.substr(authority_start, at_pos - authority_start);
    auto colon_pos = userinfo.find(':');
    if (colon_pos == std::string_view::npos) {
        return std::string(url);
    }
    // Replace password with ***
    std::string result;
    result.reserve(url.size());
    result.append(url.substr(0, authority_start + colon_pos + 1));
    result.append("***");
    result.append(url.substr(at_pos));
    return result;
}

} // namespace ag::dns
