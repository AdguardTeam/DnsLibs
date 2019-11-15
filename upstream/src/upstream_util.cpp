#include <upstream_util.h>

std::pair<std::string_view, std::string_view> ag::util::split_host_port(std::string_view address_string) {

    if (!address_string.empty() && address_string.front() == '[') {
        auto pos = address_string.find("]:");
        if (pos != std::string_view::npos) {
            return {address_string.substr(1, pos - 1), address_string.substr(pos + 2)};
        } else if (address_string.back() == ']') {
            return {address_string.substr(1, address_string.size() - 2), {}};
        }
    } else {
        auto pos = address_string.find(':');
        if (pos != std::string_view::npos) {
            return {address_string.substr(0, pos), address_string.substr(pos + 1)};
        }
    }
    return {address_string, {}};
}

std::string ag::util::join_host_port(std::string_view host, std::string_view port) {
    if (host.find(':') != std::string_view::npos) {
        std::string result = "[";
        result += host;
        result += "]:";
        result += port;
        return result;
    }
    std::string result{host};
    result += ":";
    result += port;
    return result;
}

timeval ag::util::duration_to_timeval(std::chrono::microseconds usecs) {
    timeval tv;
    int denom = decltype(usecs)::period::den;
    tv.tv_sec = long(usecs.count() / denom);
    tv.tv_usec = long(usecs.count() % denom);
    return tv;
}
