#include <cerrno>
#include <cstring>
#include <ag_sys.h>

#if defined(__linux__) || defined(__LINUX__) || defined(__MACH__)
#include <sys/resource.h>

int ag::sys::error_code() {
    return errno;
}

std::string ag::sys::error_string(int err) {
    return strerror(err);
}

size_t ag::sys::current_rss() {
    struct rusage ru = {};
    getrusage(RUSAGE_SELF, &ru);
    #if defined(__MACH__)
        return ru.ru_maxrss / 1024l;
    #else
        return ru.ru_maxrss;
    #endif
}

#elif defined(_WIN32)
#include <windows.h>
#include <stdio.h>
#include <psapi.h>
#include <errno.h>
#include "common/utils.h"

int ag::sys::error_code() {
    int err;
    _get_errno(&err);
    return err;
}

std::string ag::sys::error_string(int err) {
    return ag::utils::from_wstring(_wcserror(err));
}

size_t ag::sys::current_rss() {
    PROCESS_MEMORY_COUNTERS pmc;
    if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
        return pmc.WorkingSetSize / 1024l;
    }
    return 0;
}

#else
    #error not supported
#endif
