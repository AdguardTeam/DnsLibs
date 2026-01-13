#pragma once

#include "tcpip_common.h"

namespace ag {

/**
 * Initialize libuv LWIP port
 * @param ctx TCP/IP context
 * @return ERR_OK if success, ERR_ALREADY if LWIP was already initialized
 */
int libuv_lwip_init(TcpipCtx *ctx);

/**
 * Deinitialize libuv LWIP port
 */
void libuv_lwip_free();

} // namespace ag
