#pragma once

#ifndef _WIN32
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <arpa/inet.h>
#else
#include <winsock2.h>
#include <ws2tcpip.h>
#include <io.h>

typedef int sa_family_t;

#define close _close
#define write _write

#ifndef timercmp
#define timercmp(tvp, uvp, cmp)                                         \
	(((tvp)->tv_sec == (uvp)->tv_sec) ?                             \
	    ((tvp)->tv_usec cmp (uvp)->tv_usec) :                       \
	    ((tvp)->tv_sec cmp (uvp)->tv_sec))
#endif
#ifndef timeradd
#define timeradd(tvp, uvp, vvp)                                         \
	do {                                                            \
	        (vvp)->tv_sec = (tvp)->tv_sec + (uvp)->tv_sec;          \
	        (vvp)->tv_usec = (tvp)->tv_usec + (uvp)->tv_usec;       \
	        if ((vvp)->tv_usec >= 1000000) {                        \
	                (vvp)->tv_sec++;                                \
	                (vvp)->tv_usec -= 1000000;                      \
	        }                                                       \
	} while (0)
#endif
#endif

