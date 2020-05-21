// AdGuard extenstions to LDNS
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Return the last error occurred on `sockfd`.
 */
int ag_ldns_socket_geterror(int sockfd);

/**
 * Set the last network error to `error`.
 * For use inside LDNS code. This is thread-local.
 */
void ag_ldns_set_socket_error(int error);

/**
 * Return the last network error and set the error to 0.
 * This can be called immediately after `ldns_udp_send` returns
 * `LDNS_STATUS_NETWORK_ERR` or `LDNS_STATUS_SOCKET_ERROR`
 * to retrieve the actual error (`errno` on UNIX, or `WSAGetLastError` on Windows).
 */
int ag_ldns_check_socket_error();

#ifdef __cplusplus
}
#endif
