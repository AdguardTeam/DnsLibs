#pragma once


#include <cstdlib>
#include <cstddef>
#include <string>


namespace ag::dns::sys {

    /**
     * @brief      Get system error code
     */
    int error_code();

    /**
     * @brief      Get system error description by code
     */
    std::string error_string(int err);

    /**
     * @brief      Get current RSS of the running process (in kilobytes)
     */
    size_t current_rss();

} // namespace ag::dns::sys
