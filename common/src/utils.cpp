#include <algorithm>
#include <cstdio>
#include <cstdarg>
#include <cstring>
#include <array>
#include <locale>
#include <codecvt>
#include <ag_utils.h>

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

std::string ag::utils::fmt_string(const char *fmt, ...) {
    va_list va;
    va_start(va, fmt);
    int r = vsnprintf(nullptr, 0, fmt, va);
    va_end(va);
    if (r < 0) {
        return {};
    }

    std::string s;
    s.resize(r + 1);

    va_start(va, fmt);
    r = vsnprintf(&s[0], s.capacity(), fmt, va);
    va_end(va);
    if (r < 0) {
        return {};
    }
    s.resize(r);

    return s;
}

bool ag::utils::is_valid_ip4(std::string_view str) {
    if (str.end() != std::find_if(str.begin(), str.end(),
            [] (int ch) -> bool { return !(std::isdigit(ch) || ch == '.'); })) {
        return false;
    }

    std::vector<std::string_view> parts = ag::utils::split_by(str, '.');
    if (parts.size() != 4) {
        return false;
    }

    char buf[4];
    for (const std::string_view &p : parts) {
        if (p.length() > 3) {
            return false;
        }
        std::memcpy(buf, p.data(), p.length());
        buf[p.length()] = '\0';
        if (255 < std::atoi(buf)) {
            return false;
        }
    }
    return true;
}

bool ag::utils::is_valid_ip6(std::string_view str) {
    if (str.end() != std::find_if(str.begin(), str.end(),
            [] (int ch) -> bool {
                return !(std::isdigit(ch)
                    || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F')
                    || ch == ':' || ch == '.');
            })) {
        return false;
    }

    static constexpr std::string_view COMPRESSED_BITS = "::";

    // check "::address" and "address::" formats
    if ((str.front() == ':' && !ag::utils::starts_with(str, COMPRESSED_BITS))
            || (str.back() == ':' && !ag::utils::ends_with(str, COMPRESSED_BITS))) {
        return false;
    }

    // check that string has no more than one "::" and there is no ":::"
    size_t compress_num = 0;
    size_t seek = 0;
    while (true) {
        seek = str.find(COMPRESSED_BITS, seek);
        if (seek == str.npos) {
            break;
        }
        ++compress_num;
        if (seek < str.length() - COMPRESSED_BITS.length()
                && str[seek + COMPRESSED_BITS.length()] == ':') {
            return false;
        }
        seek += COMPRESSED_BITS.length();
    }
    if (compress_num > 1) {
        return false;
    }

    std::vector<std::string_view> parts = ag::utils::split_by(str, ':');
    if (parts.size() > 8) {
        return false;
    }

    for (size_t i = 0; i < parts.size(); ++i) {
        const std::string_view &p = parts[i];
        if (p.length() > 4) {
            if (i != parts.size() - 1) {
                return false;
            } else {
                // last one may be an ip4 address
                return is_valid_ip4(p);
            }
        }
    }

    return true;
}

std::wstring ag::utils::to_wstring(std::string_view sv) {
    return std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes(sv.begin(), sv.end());
}

std::string ag::utils::from_wstring(std::wstring_view wsv) {
    return std::wstring_convert<std::codecvt_utf8<wchar_t>>().to_bytes(wsv.begin(), wsv.end());
}
