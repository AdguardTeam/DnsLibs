#include <cerrno>
#include <cstring>

#include "common/utils.h"
#include "dns/common/sys.h"

#if defined(__linux__) || defined(__LINUX__) || defined(__MACH__)
#include <sys/resource.h>
#elif defined(_WIN32)
#include <windows.h>
#include <errno.h>
#include <psapi.h>
#include <stdio.h>
#endif

namespace ag::dns::sys {

#if defined(__linux__) || defined(__LINUX__) || defined(__MACH__)

int error_code() {
    return errno;
}

std::string error_string(int err) {
    return strerror(err);
}

size_t current_rss() {
    struct rusage ru = {};
    getrusage(RUSAGE_SELF, &ru);
#if defined(__MACH__)
    return ru.ru_maxrss / 1024l;
#else
    return ru.ru_maxrss;
#endif
}

#elif defined(_WIN32)

int error_code() {
    int err;
    _get_errno(&err);
    return err;
}

std::string error_string(int err) {
    return ag::utils::from_wstring(_wcserror(err));
}

size_t current_rss() {
    PROCESS_MEMORY_COUNTERS pmc;
    if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
        return pmc.WorkingSetSize / 1024l;
    }
    return 0;
}

#else
#error not supported
#endif

} // namespace ag::dns::sys
