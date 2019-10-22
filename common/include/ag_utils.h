#pragma once


#include <string>
#include <string_view>
#include <vector>
#include <array>
#include <algorithm>
#include <utility>
#include <type_traits>
#include <functional>


namespace ag::utils {

    /**
     * @brief      Transform string in lowercase
     */
    static inline std::string to_lower(std::string_view str) {
        std::string lwr;
        lwr.reserve(str.length());
        std::transform(str.cbegin(), str.cend(), std::back_inserter(lwr), (int (*)(int))std::tolower);
        return lwr;
    }

    /**
     * @brief      Trim whitespaces-only prefix and suffix
     */
    static inline void trim(std::string &s) {
        s.erase(s.begin(), std::find_if(s.begin(), s.end(), std::not_fn((int(*)(int))std::isspace)));
        s.erase(std::find_if(s.rbegin(), s.rend(), std::not_fn((int(*)(int))std::isspace)).base(), s.end());
    }

    /**
     * @brief      Trim whitespaces-only prefix and suffix
     */
    static inline void trim(std::string_view &str) {
        auto pos1 = std::find_if(str.begin(), str.end(), std::not_fn((int(*)(int))std::isspace));
        if (pos1 != str.end()) {
            str.remove_prefix(std::distance(str.begin(), pos1));
        }
        auto pos2 = std::find_if(str.rbegin(), str.rend(), std::not_fn((int(*)(int))std::isspace));
        if (pos2 != str.rend()) {
            str.remove_suffix(std::distance(str.rbegin(), pos2));
        }
    }

    /**
     * @brief      Check if string starts with prefix
     */
    static inline bool starts_with(std::string_view str, std::string_view prefix) {
        return str.length() >= prefix.length()
                && 0 == str.compare(0, prefix.length(), prefix);
    }

    /**
     * @brief      Check if string ends with suffix
     */
    static inline bool ends_with(std::string_view str, std::string_view suffix) {
        return str.length() >= suffix.length()
                && 0 == str.compare(str.length() - suffix.length(), suffix.length(), suffix);
    }

    /**
     * @brief      Splits string by delimiter
     */
    std::vector<std::string_view> split_by(std::string_view str, int delim);
    std::vector<std::string_view> split_by(std::string_view str, std::string_view delim);

    /**
     * @brief      Splits string by any character in delimiters
     */
    std::vector<std::string_view> split_by_any_of(std::string_view str, std::string_view delim);

    /**
     * @brief      Split string by first found delimiter for 2 parts
     */
    std::array<std::string_view, 2> split2_by(std::string_view str, int delim);

    /**
     * @brief      Split string by last found delimiter for 2 parts
     */
    std::array<std::string_view, 2> rsplit2_by(std::string_view str, int delim);

    /**
     * @brief      Join parts into a single string
     */
    template<typename T>
    static inline std::string join(const T &parts) {
        static_assert(std::is_same_v<typename T::value_type, std::string>
            || std::is_same_v<typename T::value_type, std::string_view>,
            "`ag::join` accepts only `std::string` and `std::string_view`");
        std::string s;
        size_t len = 0;
        for (const auto &p : parts) {
            len += p.length();
        }
        s.reserve(len);
        for (const auto &p : parts) {
            s.append(p.data(), p.length());
        }
        return s;
    }

    /**
     * @brief      Create string from a format string
     */
    std::string fmt_string(const char *fmt, ...);

    /**
     * @brief      Check if string is a valid ipv4 address
     */
    bool is_valid_ip4(std::string_view str);

    /**
     * @brief      Check if string is a valid ipv6 address
     */
    bool is_valid_ip6(std::string_view str);

    /**
     * @brief      Calculate hash of string
     */
    static inline uint32_t hash(std::string_view str) {
        uint32_t hash = 5381;
        for (size_t i = 0; i < str.length(); ++i) {
            hash = (hash * 33) ^ (uint32_t)str[i];
        }
        return hash;
    }

} // namespace ag::utils
