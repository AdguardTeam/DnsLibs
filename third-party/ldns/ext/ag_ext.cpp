#include <ldns/ag_ext.h>
#include <ldns/net.h>

static thread_local int last_error = 0;

void ag_ldns_set_socket_error(int error) {
    last_error = error;
}

int ag_ldns_check_socket_error() {
    int error = last_error;
    last_error = 0;
    return error;
}

int ag_ldns_socket_geterror(int sockfd) {
#ifndef _WIN32
    (void)sockfd;
    return errno;
#else
    // Don't clear the last error code here (e.g. using getsockopt with SO_ERROR): that may mess up LDNS
    (void)sockfd;
    return WSAGetLastError();
#endif
}
