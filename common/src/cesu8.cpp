#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <ag_cesu8.h>

ssize_t ag::cesu8_len(const char *utf8) {
    if (utf8 == NULL) {
        return -1;
    }

    int current_char_len = 0;
    int utf_chars_remaining = 0;
    size_t i = 0;
    for (const uint8_t *p = (const uint8_t *)utf8; *p; p++) {
        if (utf_chars_remaining > 0) {
            if ((*p & 0xc0) == 0x80) {
                current_char_len++;
                utf_chars_remaining--;
                if (utf_chars_remaining == 0) {
                    if (current_char_len == 4) {
                        current_char_len = 6;
                    }
                    i += current_char_len;
                }
                continue;
            } else {
                // replacement char
                i += 3;
                utf_chars_remaining = 0;
            }
        }

        if ((*p & 0x80) == 0x0) {
            i++;
        } else if ((*p & 0xe0) == 0xc0) {
            current_char_len = 1;
            utf_chars_remaining = 1;
        } else if ((*p & 0xf0) == 0xe0) {
            current_char_len = 1;
            utf_chars_remaining = 2;
        } else if ((*p & 0xf8) == 0xf0) {
            current_char_len = 1;
            utf_chars_remaining = 3;
        } else {
            // replacement char
            i += 3;
            utf_chars_remaining = 0;
        }
    }

    return i;
}



char *ag::utf8_to_cesu8(const char *utf8) {
    if (utf8 == NULL) {
        return NULL;
    }

    ssize_t modified_utf_len = cesu8_len(utf8);
    if (modified_utf_len < 0) {
        return NULL;
    }
    char *modified_utf = (char *)malloc(modified_utf_len + 1);
    if (modified_utf == NULL) {
        return NULL;
    }
    if (utf8_to_cesu8_noalloc(utf8, modified_utf, modified_utf_len + 1) < 0) {
        free(modified_utf);
        return NULL;
    }
    return modified_utf;
}

ssize_t ag::utf8_to_cesu8_noalloc(const char *utf8, char *output, size_t output_len) {
    if (utf8 == NULL) {
        return -1;
    }

    int utf_chars_remaining = 0;
    int current_uchar = 0;
    size_t i = 0;
    uint8_t *modified_utf = (uint8_t *) output;
    for (const uint8_t *p = (const uint8_t *)utf8; *p && i + 1 < output_len; p++) {
        if (utf_chars_remaining > 0) {
            if ((*p & 0xc0) == 0x80) {
                current_uchar <<= 6;
                current_uchar |= *p & 0x3f;
                utf_chars_remaining--;
                if (utf_chars_remaining == 0) {
                    if (current_uchar <= 0x7ff) {
                        if (i + 2 < output_len) {
                            modified_utf[i++] = 0xc0 + ((current_uchar >> 6) & 0x1f);
                            modified_utf[i++] = 0x80 + ((current_uchar) & 0x3f);
                        }
                    } else if (current_uchar <= 0xffff) {
                        if (i + 3 < output_len) {
                            modified_utf[i++] = 0xe0 + ((current_uchar >> 12) & 0x0f);
                            modified_utf[i++] = 0x80 + ((current_uchar >> 6) & 0x3f);
                            modified_utf[i++] = 0x80 + ((current_uchar) & 0x3f);
                        }
                    } else { // (current_uchar <= 0x10ffff) is always true
                        // Split into CESU-8 surrogate pair
                        // uchar is 21 bit.
                        // 11101101 1010yyyy 10xxxxxx 11101101 1011xxxx 10xxxxxx
                        // yyyy - top five bits minus one

                        if (i + 6 < output_len) {
                            modified_utf[i++] = 0xed;
                            modified_utf[i++] = 0xa0 + (((current_uchar >> 16) - 1) & 0x0f);
                            modified_utf[i++] = 0x80 + ((current_uchar >> 10) & 0x3f);

                            modified_utf[i++] = 0xed;
                            modified_utf[i++] = 0xb0 + ((current_uchar >> 6) & 0x0f);
                            modified_utf[i++] = 0x80 + ((current_uchar >> 0) & 0x3f);
                        }
                    }
                }
                continue;
            } else {
                // replacement char
                if (i + 3 < output_len) {
                    modified_utf[i++] = 0xef;
                    modified_utf[i++] = 0xbf;
                    modified_utf[i++] = 0xbd;
                }
                utf_chars_remaining = 0;
            }
        }

        if ((*p & 0x80) == 0x0) {
            modified_utf[i++] = *p;
        } else if ((*p & 0xe0) == 0xc0) {
            current_uchar = *p & 0x1f;
            utf_chars_remaining = 1;
        } else if ((*p & 0xf0) == 0xe0) {
            current_uchar = *p & 0x0f;
            utf_chars_remaining = 2;
        } else if ((*p & 0xf8) == 0xf0) {
            current_uchar = *p & 0x07;
            utf_chars_remaining = 3;
        } else {
            // replacement char
            if (i + 3 < output_len) {
                modified_utf[i++] = 0xef;
                modified_utf[i++] = 0xbf;
                modified_utf[i++] = 0xbd;
            }
            utf_chars_remaining = 0;
        }
    }

    modified_utf[i++] = '\0';
    return i;
}
