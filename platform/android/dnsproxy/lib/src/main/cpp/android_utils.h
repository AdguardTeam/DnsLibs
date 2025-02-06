#pragma once

#ifdef ANDROID
#include <android/log.h>
#define AG_ANDROID_LOG(prio_, tag_, fmt_, ...) __android_log_print(prio_, tag_, fmt_, ##__VA_ARGS__)
#else
#include <cstdio>
#define AG_ANDROID_LOG(prio_, tag_, fmt_, ...) std::fprintf(stderr, "[%d] %s " fmt_, prio_, tag_, ##__VA_ARGS__)
#endif
