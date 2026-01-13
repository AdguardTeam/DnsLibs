#include "libuv_lwip.h"

#include <chrono>
#include <cstdarg>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <mutex>

#include <uv.h>
#include <lwip/init.h>
#include <lwip/ip4_frag.h>
#include <lwip/ip6_frag.h>
#include <lwip/nd6.h>
#include <lwip/opt.h>
#include <lwip/priv/tcp_priv.h> // Timeout constants
#include <lwip/sys.h>
#include <lwip/timeouts.h>

#include "common/logger.h"
#include "dns/common/uv_wrapper.h"
#include "tcpip/tcpip.h"

namespace ag {

/**
 * Libuv LWIP port context
 */
typedef struct LibuvLwip {
    Logger logger{"TCPIP.LWIP"};
    dns::EventLoop *event_loop;
    int tcp_timer_active;
    dns::UvPtr<uv_timer_t> tcp_fasttmr;
    dns::UvPtr<uv_timer_t> tcp_slowtmr;
    dns::UvPtr<uv_timer_t> ip_reass_tmr;
    dns::UvPtr<uv_timer_t> ip6_reass_tmr;
    dns::UvPtr<uv_timer_t> nd6_tmr;
} LibuvLwip;

static std::mutex g_lwip_init_mutex;
static LibuvLwip *g_lwip;

// Forward declarations
static void ip_reass_timer_callback(uv_timer_t *handle);
static void ip6_reass_timer_callback(uv_timer_t *handle);
static void nd6_timer_callback(uv_timer_t *handle);
static void tcp_timer_callback(uv_timer_t *handle);

int libuv_lwip_init(TcpipCtx *ctx) {
    std::scoped_lock l(g_lwip_init_mutex);
    if (g_lwip != nullptr) {
        return ERR_ALREADY;
    }

    g_lwip = new LibuvLwip{};
    g_lwip->event_loop = ctx->parameters.event_loop;

    uv_loop_t *loop = g_lwip->event_loop->handle();

    // Initialize TCP timers (will be started on demand)
    g_lwip->tcp_fasttmr = dns::Uv<uv_timer_t>::create_with_parent(g_lwip);
    uv_timer_init(loop, g_lwip->tcp_fasttmr->raw());

    g_lwip->tcp_slowtmr = dns::Uv<uv_timer_t>::create_with_parent(g_lwip);
    uv_timer_init(loop, g_lwip->tcp_slowtmr->raw());

    // Initialize and start other timers
    g_lwip->ip_reass_tmr = dns::Uv<uv_timer_t>::create_with_parent(g_lwip);
    uv_timer_init(loop, g_lwip->ip_reass_tmr->raw());
    uv_timer_start(g_lwip->ip_reass_tmr->raw(), ip_reass_timer_callback, IP_TMR_INTERVAL, IP_TMR_INTERVAL);

    g_lwip->ip6_reass_tmr = dns::Uv<uv_timer_t>::create_with_parent(g_lwip);
    uv_timer_init(loop, g_lwip->ip6_reass_tmr->raw());
    uv_timer_start(g_lwip->ip6_reass_tmr->raw(), ip6_reass_timer_callback, IP6_REASS_TMR_INTERVAL, IP6_REASS_TMR_INTERVAL);

    g_lwip->nd6_tmr = dns::Uv<uv_timer_t>::create_with_parent(g_lwip);
    uv_timer_init(loop, g_lwip->nd6_tmr->raw());
    uv_timer_start(g_lwip->nd6_tmr->raw(), nd6_timer_callback, ND6_TMR_INTERVAL, ND6_TMR_INTERVAL);

    lwip_init();

    return ERR_OK;
}

void libuv_lwip_free() {
    if (g_lwip == nullptr) {
        return;
    }

    std::scoped_lock l(g_lwip_init_mutex);
    g_lwip->tcp_fasttmr.reset();
    g_lwip->tcp_slowtmr.reset();
    g_lwip->ip_reass_tmr.reset();
    g_lwip->ip6_reass_tmr.reset();
    g_lwip->nd6_tmr.reset();

    delete g_lwip;
    g_lwip = nullptr;
}

void libuv_lwip_log_debug(const char *message, ...) {
    if (g_lwip == nullptr) {
        return;
    }
    va_list args;
    va_start(args, message);
    char fmt_message[1024];
    int len = vsnprintf(fmt_message, 1024, message, args);
    if (len > 0 && fmt_message[len - 1] == '\n') {
        fmt_message[len - 1] = 0;
    }
    errlog(g_lwip->logger, "{}", fmt_message);
    va_end(args);
}

static void ip_reass_timer_callback(uv_timer_t *handle) {
    if (!dns::Uv<uv_timer_t>::parent_from_data(handle->data)) {
        return;
    }
    ip_reass_tmr();
}

static void ip6_reass_timer_callback(uv_timer_t *handle) {
    if (!dns::Uv<uv_timer_t>::parent_from_data(handle->data)) {
        return;
    }
    ip6_reass_tmr();
}

static void nd6_timer_callback(uv_timer_t *handle) {
    if (!dns::Uv<uv_timer_t>::parent_from_data(handle->data)) {
        return;
    }
    nd6_tmr();
}

static void tcp_timer_callback(uv_timer_t *handle) {
    auto *lwip = static_cast<LibuvLwip *>(dns::Uv<uv_timer_t>::parent_from_data(handle->data));
    if (lwip == nullptr) {
        return;
    }
    if (handle == lwip->tcp_fasttmr->raw()) {
        tcp_fasttmr();
    } else if (handle == lwip->tcp_slowtmr->raw()) {
        tcp_slowtmr();
    }

    if (!tcp_active_pcbs && !tcp_tw_pcbs) {
        uv_timer_stop(lwip->tcp_fasttmr->raw());
        uv_timer_stop(lwip->tcp_slowtmr->raw());
        lwip->tcp_timer_active = 0;
    }
}

/**
 * Called from TCP_REG when registering a new PCB:
 * the reason is to have the TCP timer only running when
 * there are active (or time-wait) PCBs.
 */
extern "C" void tcp_timer_needed() {
    /* timer is off but needed again? */
    if (g_lwip != nullptr && !g_lwip->tcp_timer_active && (tcp_active_pcbs || tcp_tw_pcbs)) {
        /* enable and start timer */
        g_lwip->tcp_timer_active = 1;
        uv_timer_start(g_lwip->tcp_fasttmr->raw(),
                tcp_timer_callback,
                TCP_FAST_INTERVAL,
                TCP_FAST_INTERVAL);
        uv_timer_start(g_lwip->tcp_slowtmr->raw(),
                tcp_timer_callback,
                TCP_SLOW_INTERVAL,
                TCP_SLOW_INTERVAL);
    }
}

extern "C" uint32_t sys_now() {
    if (g_lwip != nullptr && g_lwip->event_loop != nullptr) {
        // Use cached time from event loop (updated on each loop iteration)
        return uv_now(g_lwip->event_loop->handle());
    } else {
        // Fallback for early initialization or after cleanup
        return std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
    }
}

extern "C" void sys_timeouts_init(void) {
    LWIP_ASSERT("Please don't call lwip_init() directly, use libuv_lwip_init()", g_lwip != nullptr);
}

} // namespace ag
