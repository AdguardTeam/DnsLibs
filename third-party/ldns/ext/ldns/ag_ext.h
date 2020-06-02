// AdGuard extenstions to LDNS
#pragma once

#include <event2/util.h>

#ifdef __cplusplus
#include <ldns/buffer.h>
#include <ldns/packet.h>
#include <ldns/rdata.h>
#include <ldns/error.h>
#include <memory>
#include <ag_defs.h>

namespace ag {
using ldns_buffer_ptr = std::unique_ptr<ldns_buffer, ag::ftor<&ldns_buffer_free>>;
using ldns_pkt_ptr = std::unique_ptr<ldns_pkt, ag::ftor<&ldns_pkt_free>>;
using ldns_rdf_ptr = std::unique_ptr<ldns_rdf, ag::ftor<&ldns_rdf_free>>;

namespace utils {
/**
 * Return a description of an LDNS status code.
 * This function makes use of our extensions to LDNS
 * to provide a more detailed description for network errors.
 */
std::string ldns_status_to_str(ldns_status status);
}
}

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

/**
 * Log a message.
 * @param format printf-format
 * @param ... arguments
 */
void ag_ldns_log(const char *format, ...);

/**
 * @return 1 if should log, 0 otherwise. 
 */
int ag_ldns_should_log();

#ifdef __cplusplus
}
#endif
