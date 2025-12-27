#include "android_res_api.h"

#ifdef __ANDROID__

#include "common/logger.h"
#include <android/api-level.h>

extern "C" {
int android_res_nsend(net_handle_t network, const uint8_t *msg, size_t msglen, uint32_t flags) __attribute__((weak));
int android_res_nresult(int fd, int *rcode, uint8_t *answer, size_t anslen) __attribute__((weak));
void android_res_cancel(int nsend_fd) __attribute__((weak));
}

namespace ag::dns {

static Logger g_log{"AndroidResApi"};

bool AndroidResApi::is_available() {
    static bool checked = false;
    static bool available = false;

    if (checked) {
        return available;
    }

    checked = true;

    int api_level = android_get_device_api_level();
    if (api_level < 29) {
        infolog(g_log, "API level {} < 29, android_res_* functions not available", api_level);
        return false;
    }

    infolog(g_log, "API level {} >= 29, checking weak symbols", api_level);

    available = (android_res_nsend != nullptr && android_res_nresult != nullptr && android_res_cancel != nullptr);

    infolog(g_log, "Weak symbols: nsend={}, nresult={}, cancel={}", (void *) android_res_nsend,
            (void *) android_res_nresult, (void *) android_res_cancel);

    infolog(g_log, "android_res_* functions available: {}", available ? "YES" : "NO");

    return available;
}

int AndroidResApi::nsend(net_handle_t network, const uint8_t *msg, size_t msglen, uint32_t flags) {
    if (!android_res_nsend) {
        errlog(g_log, "nsend: weak symbol is null");
        return -1;
    }
    int result = android_res_nsend(network, msg, msglen, flags);
    dbglog(g_log, "nsend(network={}, msglen={}, flags={}) = {}", (unsigned long long) network, msglen, flags, result);
    return result;
}

int AndroidResApi::nresult(int fd, int *rcode, uint8_t *answer, size_t anslen) {
    if (!android_res_nresult) {
        errlog(g_log, "nresult: weak symbol is null");
        return -1;
    }
    int result = android_res_nresult(fd, rcode, answer, anslen);
    dbglog(g_log, "nresult(fd={}) = {}, rcode={}", fd, result, rcode ? *rcode : -1);
    return result;
}

void AndroidResApi::cancel(int nsend_fd) {
    if (!android_res_cancel) {
        errlog(g_log, "cancel: weak symbol is null");
        return;
    }
    dbglog(g_log, "cancel(fd={})", nsend_fd);
    android_res_cancel(nsend_fd);
}

} // namespace ag::dns

#endif // __ANDROID__
