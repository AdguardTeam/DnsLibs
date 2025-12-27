#pragma once

#ifdef __ANDROID__

#include <cstddef>
#include <cstdint>

// Forward declaration to avoid including multinetwork.h
typedef uint64_t net_handle_t;

namespace ag::dns {

/**
 * Android NDK DNS resolver API wrapper.
 * Provides weak linking and runtime availability checks for android_res_* functions.
 * These functions are only available from API level 29+.
 */
class AndroidResApi {
public:
    AndroidResApi() = delete;
    AndroidResApi(const AndroidResApi &) = delete;
    AndroidResApi(AndroidResApi &&) = delete;
    AndroidResApi &operator=(const AndroidResApi &) = delete;
    AndroidResApi &operator=(AndroidResApi &&) = delete;
    ~AndroidResApi() = delete;

    /**
     * Check if Android NDK DNS resolver functions are available at runtime.
     * @return true if all required functions are available, false otherwise
     */
    static bool is_available();

    /**
     * Send a DNS query using android_res_nsend.
     * @param network Network handle to use for the query
     * @param msg DNS query packet data
     * @param msglen Length of the DNS query packet
     * @param flags Query flags
     * @return File descriptor for the query, or -1 on error
     */
    static int nsend(net_handle_t network, const uint8_t *msg, size_t msglen, uint32_t flags);

    /**
     * Get the result of a DNS query using android_res_nresult.
     * @param fd File descriptor returned by nsend
     * @param rcode Pointer to store the DNS response code
     * @param answer Buffer to store the DNS response
     * @param anslen Size of the answer buffer
     * @return Length of the response, or negative error code
     */
    static int nresult(int fd, int *rcode, uint8_t *answer, size_t anslen);

    /**
     * Cancel a DNS query using android_res_cancel.
     * @param nsend_fd File descriptor returned by nsend
     */
    static void cancel(int nsend_fd);
};

} // namespace ag::dns

#endif // __ANDROID__
