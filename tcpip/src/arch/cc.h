/**
 * Libuv LWIP port compiler macros
 */

#ifndef ARCH_CC_H
#define ARCH_CC_H

/**
 * Custom logger function for LWIP, uses common logger
 * @param message Format string
 * @param args... Format arguments
 */
void libuv_lwip_log_debug(const char *message, ...);
#undef LWIP_PLATFORM_DIAG
#define LWIP_PLATFORM_DIAG(x)                                                                                          \
    do {                                                                                                               \
        libuv_lwip_log_debug x;                                                                                        \
    } while (0)


// Determine endianess
#if defined(_WIN32) && !defined(__clang__)

#define NOCRYPT // don't conflict with openssl
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#undef BIG_ENDIAN
#define BIG_ENDIAN REG_DWORD_BIG_ENDIAN
#undef LITTLE_ENDIAN
#define LITTLE_ENDIAN REG_DWORD_LITTLE_ENDIAN
#undef BYTE_ORDER
#define BYTE_ORDER REG_DWORD

#else

#undef BIG_ENDIAN
#define BIG_ENDIAN __ORDER_BIG_ENDIAN__
#undef LITTLE_ENDIAN
#define LITTLE_ENDIAN __ORDER_LITTLE_ENDIAN__
#undef BYTE_ORDER
#define BYTE_ORDER __BYTE_ORDER__

#endif // defined(_WIN32) && !defined(__clang__)

// Use byteswapping operations on compiler/system (for optimization)
#define LWIP_DONT_PROVIDE_BYTEORDER_FUNCTIONS 1
#ifdef _WIN32
#define SWAP_BYTES_IN_WORD(w) _byteswap_ushort(w)
#else
#define SWAP_BYTES_IN_WORD(w) __builtin_bswap16(w)
#endif

#if NO_SYS
#define LWIP_NO_UNISTD_H 1
#ifdef _WIN32
#include <basetsd.h>
#define SSIZE_MAX MAXSSIZE_T
#endif
#endif

// Struct packing
#ifdef _WIN32
#define PACK_STRUCT_USE_INCLUDES 1
#endif

#endif /* ARCH_CC_H */
