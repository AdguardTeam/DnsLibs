#include <thread>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <intrin.h>

extern "C"
int ffs(int i) {
    unsigned long res = 0;
    if (!_BitScanForward(&res, i)) {
        return 0;
    }
    return res;
}

extern "C"
int ffsl(long int i) {
    return ffs(i);
}

extern "C"
unsigned int sleep(unsigned int seconds) {
    std::this_thread::sleep_for(std::chrono::seconds(seconds));
    return 0;
}

extern "C" int evutil_ascii_strcasecmp(const char *str1, const char *str2);
extern "C"
int strcasecmp(const char *s1, const char *s2) {
    return evutil_ascii_strcasecmp(s1, s2);
}

extern "C" int evutil_ascii_strncasecmp(const char *str1, const char *str2, size_t n);
extern "C"
int strncasecmp(const char *s1, const char *s2, size_t n) {
    return evutil_ascii_strncasecmp(s1, s2, n);
}

struct timeval;
struct timezone;
extern "C" int evutil_gettimeofday(struct timeval *tv, struct timezone *tz);
extern "C"
int gettimeofday(struct timeval *tp, void *tzp) {
    return evutil_gettimeofday(tp, (struct timezone *) tzp);
}
