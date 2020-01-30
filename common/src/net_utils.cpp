#include <ag_net_utils.h>
#include <ag_socket_address.h>

std::pair<std::string_view, std::string_view> ag::utils::split_host_port(std::string_view address_string) {
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
            auto rpos = address_string.rfind(':');
            if (pos != rpos) { // This is an IPv6 address without a port
                return {address_string, {}};
            }
            return {address_string.substr(0, pos), address_string.substr(pos + 1)};
        }
    }
    return {address_string, {}};
}

std::string ag::utils::join_host_port(std::string_view host, std::string_view port) {
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

timeval ag::utils::duration_to_timeval(std::chrono::microseconds usecs) {
    static constexpr intmax_t denom = decltype(usecs)::period::den;
    return {
        .tv_sec = static_cast<decltype(timeval::tv_sec)>(usecs.count() / denom),
        .tv_usec = static_cast<decltype(timeval::tv_usec)>(usecs.count() % denom)
    };
}

std::string ag::utils::addr_to_str(uint8_view v) {
    socket_address addr{v, 0};
    if (!addr.valid()) {
        return {};
    }
    return std::string(split_host_port(addr.str()).first);
}
