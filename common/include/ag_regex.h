#pragma once

#include <string_view>
#include <string>
#include <ag_logger.h>
#include <pcre2.h>


namespace ag {

class regex {
public:
    explicit regex(std::string_view text)
        : re(compile_regex(text))
    {}

    ~regex() {
        pcre2_code_free(this->re);
    }

    regex(const regex &other) {
        *this = other;
    }

    regex(regex &&other) {
        *this = std::move(other);
    }

    regex &operator=(const regex &other) {
        this->re = pcre2_code_copy(other.re);
        return *this;
    }

    regex &operator=(regex &&other) {
        this->re = other.re;
        other.re = nullptr;
        return *this;
    }

    /**
     * @brief      Check if regex compiled successfully
     */
    bool is_valid() const { return this->re != nullptr; }

    /**
     * @brief      Match string against regex
     * @param[in]  str   string to match
     * @return     True if matches, false otherwise
     */
    bool match(std::string_view str) const {
        if (!is_valid()) {
            return false;
        }

        pcre2_match_data *match_data = pcre2_match_data_create_from_pattern(this->re, nullptr);
        int retval = pcre2_match(this->re, (PCRE2_SPTR8)str.data(), str.length(),
            0, 0, match_data, nullptr);
        pcre2_match_data_free(match_data);
        if (retval < 0 && retval != PCRE2_ERROR_NOMATCH && retval != PCRE2_ERROR_PARTIAL) {
            SPDLOG_ERROR("Matching string '{}' failed against URL: %d", str, retval);
        }
        return retval >= 0;
    }

    /**
     * @brief      Replace string by regex
     * @param[in]  subject      string to process
     * @param[in]  replacement  replacement string
     * @return     Apply result (empty in case of error)
     */
    std::string replace(std::string_view subject, std::string_view replacement) const {
        uint32_t options = PCRE2_SUBSTITUTE_GLOBAL
            | PCRE2_SUBSTITUTE_UNSET_EMPTY
            | PCRE2_SUBSTITUTE_EXTENDED;

        std::string result;
        size_t result_length = subject.length() + 1;
        result.resize(result_length - 1);

        int retval = pcre2_substitute(this->re,
            (PCRE2_SPTR8)subject.data(), subject.length(), 0, options, nullptr, nullptr,
            (PCRE2_SPTR8)replacement.data(), replacement.length(),
            (PCRE2_UCHAR8*)result.data(), &result_length);
        if (retval == PCRE2_ERROR_NOMEMORY) {
            result.resize(result_length - 1);
            retval = pcre2_substitute(this->re,
                (PCRE2_SPTR8)subject.data(), subject.length(), 0, options, nullptr, nullptr,
                (PCRE2_SPTR8)replacement.data(), replacement.length(),
                (PCRE2_UCHAR8*)result.data(), &result_length);
        }
        if (retval >= 0) {
            result.resize(result_length);
        } else if (retval < 0) {
            PCRE2_UCHAR err_message[256];
            pcre2_get_error_message(retval, err_message, sizeof(err_message));
            SPDLOG_ERROR("Failed remove special characters from '%s': %s", subject, err_message);
            result.clear();
        }
        return result;
    }

private:
    pcre2_code *re;

    static pcre2_code *compile_regex(std::string_view text) {
        int err = 0;
        PCRE2_SIZE err_offset = 0;
        pcre2_code *re = pcre2_compile((PCRE2_SPTR8)text.data(), text.length(),
            0, &err, &err_offset, nullptr);
        if (re == nullptr) {
            PCRE2_UCHAR error_message[256];
            pcre2_get_error_message(err, error_message, sizeof(error_message));
            SPDLOG_ERROR("Failed to compile regex {}: {} (offset={})",
                text, error_message, err_offset);
            return nullptr;
        }
        return re;
    }
};

} // namespace ag
