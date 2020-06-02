#include <ldns/ag_ext.h>
#include <ldns/net.h>
#include <cstdarg>
#include <ag_utils.h>
#include <ag_logger.h>
#include <event2/util.h>

static thread_local int last_error = 0;

static ag::logger logger = ag::create_logger("LDNS");

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

void ag_ldns_log(const char *format, ...) {
    va_list args;
    va_start(args, format);
    char buf[512];
    std::vsnprintf(buf, sizeof(buf), format, args);
    va_end(args);
    dbglog(logger, "{}", buf);
}

int ag_ldns_should_log() {
    return logger->should_log(spdlog::level::debug);
}

// Had to fish this out of the ag:: namespace to avoid collision
// between `to_string_view` declared in ag:: and fmt::
static std::string ldns_status_to_str_impl(ldns_status status) {
    if (status == LDNS_STATUS_SOCKET_ERROR || status == LDNS_STATUS_NETWORK_ERR) {
        if (int ag_error = ag_ldns_check_socket_error(); ag_error != 0) {
            auto err_str = AG_FMT("LDNS network error: {} ({})", ag_error, evutil_socket_error_to_string(ag_error));
            return err_str;
        }
    }
    return ldns_get_errorstr_by_id(status);
}

std::string ag::utils::ldns_status_to_str(ldns_status status) {
    return ldns_status_to_str_impl(status);
}
