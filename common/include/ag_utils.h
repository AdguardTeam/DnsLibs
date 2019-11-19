#pragma once


#include <chrono>
#include <string>
#include <string_view>
#include <sstream>
#include <iomanip>
#include <iterator>
#include <vector>
#include <array>
#include <algorithm>
#include <utility>
#include <type_traits>
#include <functional>
#include <optional>
#include <ag_defs.h>

/**
 * Macros to create constexpr value and type to check expression
 * @example AG_UTILS_DECLARE_CHECK_EXPRESSION(has_f, std::declval<T>().f)
 *          // Generates template<typename T> inline constexpr bool has_f;
 *          ...
 *          template<typename SomeType>
 *          void f() {
 *              static_assert(has_f<SomeType>, "Failed: SomeType::f does not exists");
 *          }
 */
#define AG_UTILS_DECLARE_CHECK_EXPRESSION(TRAITS_NAME, ...) \
namespace detail { \
template<typename TypeToCheck> \
struct TRAITS_NAME ## _impl { \
private: \
    template<typename T> \
    static auto test(void*) -> decltype(static_cast<void>(__VA_ARGS__), std::true_type{}); \
    template<typename> \
    static std::false_type test(...); \
public: \
    /* TODO use std::is_detected since C++20 */ \
    static constexpr auto value = decltype(test<TypeToCheck>(nullptr)){}; \
}; \
} \
template<typename T> \
struct TRAITS_NAME ## _type : std::bool_constant<detail::TRAITS_NAME ## _impl<T>::value> {}; \
template<typename T> \
inline constexpr bool TRAITS_NAME = TRAITS_NAME ## _type<T>::value;

/**
 * Macros to create constexpr value and type to check expression depended from number of parameters
 * @example AG_UTILS_DECLARE_CHECK_EXPRESSION(has_f, T((Is, convertible_to_any{})...))
 *          // Generates template<typename T, size_t N> inline constexpr bool can_init;
 *          ...
 *          template<typename SomeType>
 *          void f() {
 *              static_assert(can_init<SomeType, 2>, "Failed: Cant init with 2 params SomeType::SomeType(arg1, arg2)");
 *          }
 */
#define AG_UTILS_DECLARE_CHECK_EXPRESSION_WITH_N(TRAITS_NAME, ...) \
namespace detail { \
template<typename TypeToCheck, size_t N> \
struct TRAITS_NAME ## _impl { \
private: \
    template<typename T, size_t... Is> \
    static auto test(void*, std::integer_sequence<size_t, Is...>) -> \
            decltype(static_cast<void>(__VA_ARGS__), std::true_type{}); \
    template<typename> \
    static std::false_type test(...); \
public: \
    static constexpr auto value = decltype(test<TypeToCheck>(nullptr, std::make_index_sequence<N>())){}; \
}; \
} \
template<typename T, size_t N> \
struct TRAITS_NAME ## _type : std::bool_constant<detail:: TRAITS_NAME ## _impl<T, N>::value> {}; \
template<typename T, size_t N> \
inline constexpr bool TRAITS_NAME = TRAITS_NAME ## _type<T, N>::value;

namespace ag::utils {

/**
 * Transform string in lowercase
 */
static inline std::string to_lower(std::string_view str) {
    std::string lwr;
    lwr.reserve(str.length());
    std::transform(str.cbegin(), str.cend(), std::back_inserter(lwr), (int (*)(int))std::tolower);
    return lwr;
}

/**
 * Trim whitespaces-only prefix and suffix
 */
static inline void trim(std::string &s) {
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), std::not_fn((int(*)(int))std::isspace)));
    s.erase(std::find_if(s.rbegin(), s.rend(), std::not_fn((int(*)(int))std::isspace)).base(), s.end());
}

/**
 * Trim whitespaces-only prefix and suffix
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
 * Check if string starts with prefix
 */
static inline bool starts_with(std::string_view str, std::string_view prefix) {
    return str.length() >= prefix.length()
            && 0 == str.compare(0, prefix.length(), prefix);
}

/**
 * Check if string ends with suffix
 */
static inline bool ends_with(std::string_view str, std::string_view suffix) {
    return str.length() >= suffix.length()
            && 0 == str.compare(str.length() - suffix.length(), suffix.length(), suffix);
}

/**
 * Splits string by delimiter
 */
std::vector<std::string_view> split_by(std::string_view str, int delim);
std::vector<std::string_view> split_by(std::string_view str, std::string_view delim);

/**
 * Splits string by any character in delimiters
 */
std::vector<std::string_view> split_by_any_of(std::string_view str, std::string_view delim);

/**
 * Split string by first found delimiter for 2 parts
 */
std::array<std::string_view, 2> split2_by(std::string_view str, int delim);

/**
 * Split string by last found delimiter for 2 parts
 */
std::array<std::string_view, 2> rsplit2_by(std::string_view str, int delim);

/**
 * Check is T has `reserve(size_t{...})` member function or not
 * @example static_assert(has_reserve< std::vector<int> >::value, "std::vector<int> has reserve function");
 *          static_assert(has_reserve< std::list<int> >::value == false, "std::list<int> has no reserve function");
 */
AG_UTILS_DECLARE_CHECK_EXPRESSION(has_reserve, std::declval<T>().reserve(std::declval<size_t>()))

/**
 * Join parts into a single container
 */
template<typename R, typename T>
static inline R join(const T &parts) {
    R result{};
    if constexpr (has_reserve<R>) {
        size_t size = 0;
        for (const auto &p : parts) {
            size += std::size(p);
        }
        result.reserve(size);
    }
    for (const auto &p : parts) {
        result.insert(std::cend(result), std::cbegin(p), std::cend(p));
    }
    return result;
}

/**
 * Join parts into a single string
 */
template<typename T>
static inline std::string join(const T &parts) {
    static_assert(std::is_same_v<typename T::value_type, std::string>
        || std::is_same_v<typename T::value_type, std::string_view>,
        "`ag::join` accepts only `std::string` and `std::string_view`");
    return join<std::string>(parts);
}

/**
 * Join parts into a single container from comma-separated parts
 */
template<typename R, typename... Ts>
static inline std::enable_if_t<sizeof...(Ts) >= 2, R> join(const Ts&... parts) {
    R result{};
    if constexpr (has_reserve<R>) {
        result.reserve((... + parts.size()));
    }
    (... , result.insert(std::cend(result), std::cbegin(parts), std::cend(parts)));
    return result;
}

/**
 * Create string from a format string
 */
std::string fmt_string(const char *fmt, ...);

/**
 * Check if string is a valid ipv4 address
 */
bool is_valid_ip4(std::string_view str);

/**
 * Check if string is a valid ipv6 address
 */
bool is_valid_ip6(std::string_view str);

/**
 * Calculate hash of string
 */
static inline uint32_t hash(std::string_view str) {
    uint32_t hash = 5381;
    for (size_t i = 0; i < str.length(); ++i) {
        hash = (hash * 33) ^ (uint32_t)str[i];
    }
    return hash;
}

/**
 * Convert UTF-8 string to wide char string
 * @param sv UTF-8 string
 * @return Wide char string
 */
std::wstring to_wstring(std::string_view sv);

/**
 * Convert wide char string to UTF-8 string
 * @param wsv Wide char string
 * @return UTF-8 string
 */
std::string from_wstring(std::wstring_view wsv);

/**
 * Create string view from container-like value with data() and size() member functions
 * @param value Value
 * @return String view pointed to value's data and size
 */
template<typename T>
static inline constexpr auto to_string_view(const T& value) {
    return std::basic_string_view<typename T::value_type>(value.data(), value.size());
}

/**
 * Create string view from array with known size S
 * @param value Value
 * @return String view pointed to value and size S
 */
template<typename T, size_t S>
static inline constexpr auto to_string_view(const T (&value)[S]) {
    return std::basic_string_view<T>(value, S);
}

/**
 * Create std::array from C array with known size S
 * @param value Value
 * @return Array with copy of value and size S
 */
template<typename T, size_t S>
static inline auto to_array(const T (&value)[S]) {
    // TODO use std::to_array since C++20
    std::array<std::remove_cv_t<T>, S> result;
    std::move(std::cbegin(value), std::cend(value), result.begin());
    return result;
}

/**
 * Create std::array from array with size S and type T
 * @param value Value
 * @return Array with copy of value and size S
 */
template<size_t S, typename T>
static inline auto to_array(const T *value) {
    std::array<std::remove_cv_t<T>, S> result;
    std::move(value, value + S, result.begin());
    return result;
}

/**
 * Convert enum value to underlying integral type and then converts to string
 * @param value Value
 * @return String representation of integral representation of enum value
 */
template<typename T>
static inline std::enable_if_t<std::is_enum_v<T>, std::string> enum_to_string(T value) {
    return std::to_string(static_cast<std::underlying_type_t<T>>(value));
}

/**
 * Conditionally returns optional or nullopt
 * @param condition Condition
 * @param value Value
 * @return Optional with value if condition true, nullopt otherwise
 */
template<typename T>
static inline constexpr auto make_optional_if(bool condition, T&& value) {
    return condition ? std::make_optional(std::forward<T>(value)) : std::nullopt;
}

/**
 * Make unique ptr with std::free deleter
 * @param ptr Pointer to hold
 */
template<typename T>
static inline allocated_ptr<T> make_allocated_unique(T *ptr) noexcept {
    return allocated_ptr<T>{ptr};
}

/**
 * Timer measures time since creating object
 */
class timer {
public:
    /**
     * Returns elapsed time duration since creating object
     * @tparam T Duration type
     * @return Elapsed time duration since creating object
     */
    template<typename T>
    T elapsed() const {
        return std::chrono::duration_cast<T>(std::chrono::steady_clock::now() - start);
    }
private:
    std::chrono::steady_clock::time_point start = std::chrono::steady_clock::now();
};

/**
 * Create string using from time since epoch
 * @param timer Time since epoch
 * @param format Format string
 * @return String representation of timer
 */
static inline std::string time_to_str(time_t timer, std::string_view format = "%Y-%m-%d %H:%M:%S %z %Z") {
    std::stringstream ss;
    ss << std::put_time(std::localtime(&timer), format.data());
    return ss.str();
}

namespace detail {

struct convertible_to_any {
    template<typename T>
    operator T() const;
};

} // namespace detail

/**
 * Defines value list_initializable_with_n_params<T, N> to checks is posible to list init T{...with N params...}
 */
AG_UTILS_DECLARE_CHECK_EXPRESSION_WITH_N(list_initializable_with_n_params, T{(Is, convertible_to_any{})...})

namespace detail {

template<typename T, ssize_t C>
constexpr ssize_t list_init_params_count_impl(std::false_type) {
    return C - 1;
}

template<typename T, ssize_t C>
constexpr ssize_t list_init_params_count_impl(std::true_type) {
    return list_init_params_count_impl<T, C + 1>(list_initializable_with_n_params_type<T, C + 1>{});
}

} // namespace detail

/**
 * Count parameters to list init
 * @return If can't init with no parameters -1, first maximum parameters count to init otherwise
 */
template<typename T>
inline constexpr ssize_t list_init_params_count = detail::list_init_params_count_impl<T, 0>(
        list_initializable_with_n_params_type<T, 0>{});

/**
 * Checks is T has `error` member or not
 * @example struct result {
 *              std::string text;
 *              err_string error;
 *          };
 *          struct other_result {
 *              std::string text;
 *          };
 *          struct another_result {
 *              void error() {}
 *          };
 *          ...
 *          static_assert(has_error<result>, "result has `error` member value");
 *          static_assert(has_error<other_result> == false, "other_result has no `error` member value");
 *          static_assert(has_error<another_result> == false, "another_result has no `error` member value");
 */
AG_UTILS_DECLARE_CHECK_EXPRESSION(has_error, std::declval<T>().error)

namespace detail {

template<typename Result, typename F, typename... Us>
Result forward_error_impl(F&& f, Us&&... xs) {
    static_assert(sizeof...(xs) < list_init_params_count<Result>,
                  "Too much parameters to list init. Error initialized twice");
    Result result{std::forward<Us>(xs)...};
    std::forward<F>(f)(result);
    return result;
}

} // namespace detail

/**
 * Creates result struct with error. Result is default initialized or initialized with xs parameters.
 * @warning Assumed that error is last member in struct
 * @tparam Result Result type
 * @param err Error
 * @param xs Optional parameters to init result
 * @return Result with error and optional xs parameters
 */
template<typename Result, typename E, typename... Us>
std::enable_if_t<has_error<Result>, Result> forward_error(E&& err, Us&&... xs) {
    return detail::forward_error_impl<Result>(
            [&](auto& result) {
                result.error = std::forward<E>(err);
            }, std::forward<Us>(xs)...);
}

/**
 * Creates result tuple-like object with error of type err_string. Result is default initialized or initialized
 * with xs parameters.
 * @warning Assumed that error is last member in tuple-like object
 * @param err Error
 * @param xs Optional parameters to init result
 * @return Result with error and optional xs parameters
 */
template<typename Result, typename E, typename... Us>
std::enable_if_t<!has_error<Result>, Result> forward_error(E&& err, Us&&... xs) {
    return detail::forward_error_impl<Result>(
            [&](auto& result) {
                std::get<err_string>(result) = std::forward<E>(err);
            }, std::forward<Us>(xs)...);
}

/**
 * Error maker functional object for reducing boilerplate code.
 * @see forward_error
 * @example f_result f() {
 *              static constexpr ag::utils::make_error<f_result> make_error;
 *              ...
 *              auto err = g(...);
 *              if (err) {
 *                  return make_error(std::move(err));
 *              }
 *              ...
 *          }
 */
template<typename T>
class make_error {
public:
    template<typename... Ts>
    decltype(auto) operator()(Ts&&... xs) const {
        return forward_error<T>(std::forward<Ts>(xs)...);
    }
};

} // namespace ag::utils
