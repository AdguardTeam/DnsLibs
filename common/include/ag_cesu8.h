#pragma once

#include "common/defs.h"

namespace ag {

/**
 * Converts UTF-8 string to CESU-8 (or Java modified UTF-8) string
 * @param utf8 UTF-8 string
 * @return Newly allocated CESU-8 string, which is java safe, or NULL if input string is NULL
 */
char *utf8_to_cesu8(const char *utf8);

/**
 * Converts UTF-8 string to CESU-8 (or Java modified UTF-8) string
 * @param utf8 UTF-8 string
 * @param output Output buffer where will be written CESU-8 string, which is java safe
 * @param output_len Output buffer len. Must be at least cesu8_len() + 1
 * @return Number of bytes written, or -1 if input string is NULL
 */
ssize_t utf8_to_cesu8_noalloc(const char *utf8, char *output, size_t output_len);

/**
 * Calculate length on UTF-8 string coverted to CESU-8
 * @param utf8 UTF-8 string
 * @return Length of CESU-8 string, or -1 if input string is NULL
 */
ssize_t cesu8_len(const char *utf8);

}
