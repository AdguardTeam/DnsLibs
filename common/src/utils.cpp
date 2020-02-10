#include <algorithm>
#include <cstdio>
#include <cstdarg>
#include <cstring>
#include <array>
#include <locale>
#include <codecvt>
#include <ag_utils.h>
#include <ag_socket_address.h>

std::vector<std::string_view> ag::utils::split_by(std::string_view str, std::string_view delim) {
    if (str.empty()) {
        return { str };
    }

    size_t num = 1;
    size_t seek = 0;
    while (true) {
        size_t pos = str.find(delim, seek);
        if (pos != str.npos) {
            ++num;
            seek = pos + delim.length();
        } else {
            break;
        }
    }

    seek = 0;
    std::vector<std::string_view> out;
    out.reserve(num);
    for (size_t i = 0; i < num; ++i) {
        size_t start = seek;
        size_t end = str.find(delim, seek);
        if (end == str.npos) {
            end = str.length();
        }
        size_t length = end - start;
        if (length != 0) {
            std::string_view s = { &str[seek], length };
            trim(s);
            if (!s.empty()) {
                out.push_back(s);
            }
        }
        seek = end + delim.length();
    }
    out.shrink_to_fit();

    return out;
}

std::vector<std::string_view> ag::utils::split_by(std::string_view str, int delim) {
    return split_by_any_of(str, { (char*)&delim, 1 });
}

std::vector<std::string_view> ag::utils::split_by_any_of(std::string_view str, std::string_view delim) {
    if (str.empty()) {
        return { str };
    }

    size_t num = 1 + std::count_if(str.begin(), str.end(),
        [&delim] (int c) { return delim.find(c) != delim.npos; });
    size_t seek = 0;
    std::vector<std::string_view> out;
    out.reserve(num);
    for (size_t i = 0; i < num; ++i) {
        size_t start = seek;
        size_t end = str.find_first_of(delim, seek);
        if (end == str.npos) {
            end = str.length();
        }
        size_t length = end - start;
        if (length != 0) {
            std::string_view s = { &str[seek], length };
            trim(s);
            if (!s.empty()) {
                out.push_back(s);
            }
        }
        seek = end + 1;
    }
    out.shrink_to_fit();

    return out;
}

static std::array<std::string_view, 2> split2(std::string_view str, int delim, bool reverse) {
    std::string_view first;
    std::string_view second;

    size_t seek = !reverse ? str.find(delim) : str.rfind(delim);
    if (seek != str.npos) {
        first = { str.data(), seek };
        second = { str.data() + seek + 1, str.length() - seek - 1 };
    } else {
        first = str;
        second = {};
    }

    return { first, second };
}

std::array<std::string_view, 2> ag::utils::split2_by(std::string_view str, int delim) {
    return split2(str, delim, false);
}

std::array<std::string_view, 2> ag::utils::rsplit2_by(std::string_view str, int delim) {
    return split2(str, delim, true);
}

bool ag::utils::is_valid_ip4(std::string_view str) {
    ag::socket_address addr(str, 0);
    return addr.valid() && addr.c_sockaddr()->sa_family == AF_INET;
}

bool ag::utils::is_valid_ip6(std::string_view str) {
    ag::socket_address addr(str, 0);
    return addr.valid() && addr.c_sockaddr()->sa_family == AF_INET6;
}

std::wstring ag::utils::to_wstring(std::string_view sv) {
    return std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes(sv.begin(), sv.end());
}

std::string ag::utils::from_wstring(std::wstring_view wsv) {
    return std::wstring_convert<std::codecvt_utf8<wchar_t>>().to_bytes(wsv.begin(), wsv.end());
}
