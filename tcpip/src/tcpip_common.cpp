#include <cstdlib>
#include <cstring>
#include <errno.h>
#include <fcntl.h>
#include <span>
#include <vector>

#include <lwip/netdb.h>
#include <lwip/netif.h>
#include <lwip/pbuf.h>
#include <lwip/tcp.h>
#include <lwip/ip_addr.h>
#include <uv.h>

#include "libuv_lwip.h"
#include "tcp_conn_manager.h"
#include "tcpip/platform.h"
#include "tcpip/tcpip.h"
#include "tcpip/utils.h"
#include "tcpip_common.h"
#include "tcpip_util.h"
#include "udp_conn_manager.h"

namespace ag {

#define TIMER_PERIOD_S (TCPIP_DEFAULT_CONNECTION_TIMEOUT_S / 10)

/**
 * Read at most this much packets from TUN fd
 * before deferring until the next event loop iteration.
 */
static constexpr size_t TUN_READ_BUDGET = 64;

static constexpr int DEFAULT_PACKET_POOL_SIZE = 25;
static constexpr const char *NETIF_NAME = "tn";
static constexpr TimerTickNotifyFn TIMER_TICK_NOTIFIERS[] = {
        tcp_cm_timer_tick,
        udp_cm_timer_tick,
};

static void dump_packet_to_pcap(TcpipCtx *ctx, const uint8_t *data, size_t len);
static void dump_packet_iovec_to_pcap(TcpipCtx *ctx, std::span<uv_buf_t> chunks);
static void open_pcap_file(TcpipCtx *ctx, const char *pcap_filename);
static void process_input_packet(TcpipCtx *ctx, Packet *packet);
#ifdef __MACH__
static err_t tun_output_to_utun_fd(TcpipCtx *ctx, std::span<uv_buf_t> chunks, int family);
#endif /* __MACH__ */
#ifndef _WIN32
static err_t tun_output_to_fd(TcpipCtx *ctx, std::span<uv_buf_t> chunks);
#endif
static err_t tun_output_to_callback(TcpipCtx *ctx, std::span<uv_buf_t> chunks, int family);

static err_t tun_output(const struct netif *netif, const struct pbuf *packet_buffer, int family) {
    auto *ctx = (TcpipCtx *) netif->state;

    size_t chain_length = pbuf_clen(packet_buffer);
    std::vector<uv_buf_t> chunks;
    chunks.reserve(chain_length);

    size_t idx = 0;
    for (const struct pbuf *iter = packet_buffer; (idx < chain_length) && (iter != nullptr); idx++, iter = iter->next) {
        chunks.push_back(uv_buf_init((char *)iter->payload, iter->len));
    }

    tracelog(ctx->logger, "TUN output: {} bytes", (int) packet_buffer->tot_len);

    err_t err;
    if (ctx->parameters.tun_fd != -1) {
#ifdef __MACH__
        err = tun_output_to_utun_fd(ctx, {chunks.data(), chunks.size()}, family);
#elif !defined _WIN32
        err = tun_output_to_fd(ctx, {chunks.data(), chunks.size()});
#else
        err = ERR_ARG;
#endif
    } else {
        err = tun_output_to_callback(ctx, {chunks.data(), chunks.size()}, family);
    }

    if (err == ERR_OK && ctx->pcap_fd != -1) {
        dump_packet_iovec_to_pcap(ctx, {chunks.data(), chunks.size()});
    }

    return err;
}

static err_t tun_output_to_callback(TcpipCtx *ctx, std::span<uv_buf_t> chunks, int family) {
    TcpipTunOutputEvent info = {family, {chunks.size(), chunks.data()}};

    TcpipHandler *callbacks = &ctx->parameters.handler;
    callbacks->handler(callbacks->arg, TCPIP_EVENT_TUN_OUTPUT, &info);

    return ERR_OK;
}

#ifndef _WIN32
static err_t tun_output_to_fd(TcpipCtx *ctx, std::span<uv_buf_t> chunks) {
    err_t err = ERR_OK;

    /* Write packet to TUN */
    // uv_buf_t is compatible with iovec on Unix
    ssize_t written = writev(ctx->parameters.tun_fd,
            reinterpret_cast<const struct iovec *>(chunks.data()), chunks.size());
    if (-1 == written) {
        if (errno == EWOULDBLOCK) {
            err = ERR_MEM;
        } else {
            err = ERR_ABRT;
        }
    }

    return err;
}
#endif // !defined _WIN32

#ifdef __MACH__
struct UtunHdr {
    int family;
};

static err_t tun_output_to_utun_fd(TcpipCtx *ctx, std::span<uv_buf_t> chunks, int family) {
    std::vector<uv_buf_t> new_chunks;
    new_chunks.reserve(chunks.size() + 1);
    struct UtunHdr hdr = {.family = (int) htonl(family)};
    new_chunks.push_back(uv_buf_init((char *)&hdr, sizeof(hdr)));
    for (const uv_buf_t &chunk : chunks) {
        new_chunks.push_back(chunk);
    }
    return tun_output_to_fd(ctx, {new_chunks.data(), new_chunks.size()});
}
#endif /* __MACH__ */

static err_t tun_output_ipv4(struct netif *netif, struct pbuf *p, const ip4_addr_t *ip4) {
    return tun_output(netif, p, AF_INET);
}

static err_t tun_output_ipv6(struct netif *netif, struct pbuf *p, const ip6_addr_t *ip6) {
    return tun_output(netif, p, AF_INET6);
}

static err_t netif_init_cb(struct netif *netif) {
    const auto *ctx = (TcpipCtx *) netif->state;

    netif->name[0] = NETIF_NAME[0];
    netif->name[1] = NETIF_NAME[1];
    netif->output = tun_output_ipv4;
    netif->output_ip6 = tun_output_ipv6;
    netif->flags |= NETIF_FLAG_UP | NETIF_FLAG_LINK_UP;
    netif->mtu = ctx->parameters.mtu_size;

    return ERR_OK;
}

enum TunReadStatus {
    TRS_OK,     // data was read from tun device and sent to netif driver
    TRS_DROP,   // read data was malformed, so another read is required
    TRS_STOP    // no more data can be read from tun device
};

/**
 * Read data from tun device and send it to netif driver.
 * If packet is Packet was sent to netif driver, its destructor will be called on the driver's side,
 * else call Packet's destructor manually to avoid leak.
 * @param ctx context holder for tcp/ip stack
 * @param packet container for reading data from tun device
 * @return see TunReadStatus fields description
 */
#ifdef __MACH__
static TunReadStatus process_data_from_utun(TcpipCtx *ctx, Packet *packet) {
    UtunHdr hdr{};

    static constexpr int HDR_SIZE = sizeof(hdr);
    struct iovec iov[] = {
            {.iov_base = &hdr, .iov_len = HDR_SIZE}, {.iov_base = packet->data, .iov_len = ctx->parameters.mtu_size}};
    ssize_t bytes_read = readv(ctx->parameters.tun_fd, iov, std::size(iov));
    if (bytes_read <= 0) {
        if (EWOULDBLOCK != errno) {
            errlog(ctx->logger, "data from UTUN: read failed (errno={})", strerror(errno));
        }
        return TRS_STOP;
    }
    if (bytes_read < HDR_SIZE) {
        errlog(ctx->logger, "data from UTUN: read less than header size bytes");
        return TRS_DROP;
    }

    tracelog(ctx->logger, "data from UTUN: {} bytes", bytes_read);
    packet->size = bytes_read - HDR_SIZE;
    process_input_packet(ctx, packet);
    return TRS_OK;
}
#else  /* __MACH__ */
static TunReadStatus process_data_from_tun(TcpipCtx *ctx, Packet *packet) {

    ssize_t bytes_read = read(ctx->parameters.tun_fd, packet->data, ctx->parameters.mtu_size);
    if (bytes_read <= 0) {
        if (EWOULDBLOCK != errno) {
            errlog(ctx->logger, "data from TUN: read failed (errno={})", strerror(errno));
        }
        return TRS_STOP;
    }
    packet->size = bytes_read;
    tracelog(ctx->logger, "data from TUN: {} bytes", bytes_read);

    process_input_packet(ctx, packet);
    return TRS_OK;
}
#endif /* else of __MACH__ */

struct ZeroCopyPBuf {
    pbuf_custom p;
    Packet v;
};

static void zerocopy_pbuf_free(struct pbuf *buf) {
    auto *buf_custom = (ZeroCopyPBuf *) buf;
    if (buf_custom->v.destructor) {
        buf_custom->v.destructor(buf_custom->v.destructor_arg, buf_custom->v.data);
    }
    delete buf_custom;
}

static pbuf *zerocopy_pbuf_create(Packet *packet) {
    auto *buf_custom = new ZeroCopyPBuf{};
    buf_custom->p.custom_free_function = zerocopy_pbuf_free;
    buf_custom->v = *packet;

    pbuf *buffer = pbuf_alloced_custom(PBUF_RAW, buf_custom->v.size, PBUF_REF, &buf_custom->p,
            buf_custom->v.data, u16_t(buf_custom->v.size));
    if (buffer == nullptr) {
        delete buf_custom;
        return nullptr;
    }
    return buffer;
}

static void process_input_packet(TcpipCtx *ctx, Packet *packet) {
    // Dump to PCap
    if (ctx->pcap_fd != -1) {
        dump_packet_to_pcap(ctx, packet->data, packet->size);
    }

    pbuf *buffer = zerocopy_pbuf_create(packet);
    err_t result = netif_input(buffer, ctx->netif);

    if (ERR_OK != result) {
        pbuf_free(buffer);
        errlog(ctx->logger, "data from TUN: netif_input failed ({})", result);
    }
}

static void tun_poll_callback(uv_poll_t *handle, int status, int events) {
    auto ctx = (TcpipCtx *) dns::Uv<uv_poll_t>::parent_from_data(handle->data);
    if (nullptr == ctx) {
        return;
    }

    if (status < 0) {
        errlog(ctx->logger, "tun poll error: {}", uv_strerror(status));
        return;
    }

    tracelog(ctx->logger, "tun event: fd {} - events: {}{}", ctx->parameters.tun_fd,
            (events & UV_READABLE) ? " readable" : "", (events & UV_WRITABLE) ? " writable" : "");

    for (size_t i = 0; i < TUN_READ_BUDGET; ++i) {
        TunReadStatus status{};
        Packet packet = ctx->pool->get_packet();
#ifdef __MACH__
        status = process_data_from_utun(ctx, &packet);
#else
        status = process_data_from_tun(ctx, &packet);
#endif
        if (status != TRS_OK && packet.destructor) {
            packet.destructor(packet.destructor_arg, packet.data);
        }
        if (status == TRS_STOP) {
            break;
        }
    }
}

static void timer_callback(uv_timer_t *handle) {
    auto ctx = (TcpipCtx *) dns::Uv<uv_timer_t>::parent_from_data(handle->data);
    if (ctx == nullptr) {
        return;
    }
    for (auto fn : TIMER_TICK_NOTIFIERS) {
        fn(ctx);
    }
}

static bool configure_events(TcpipCtx *ctx) {
    uv_loop_t *loop = ctx->parameters.event_loop->handle();
    if (nullptr == loop) {
        errlog(ctx->logger, "configure: no event loop provided");
        return false;
    }

    if (ctx->parameters.tun_fd != -1) {
        ctx->tun_poll = dns::Uv<uv_poll_t>::create_with_parent(ctx);
        int init_result = uv_poll_init(loop, ctx->tun_poll->raw(), ctx->parameters.tun_fd);
        if (init_result < 0) {
            errlog(ctx->logger, "configure: failed to init TUN poll: {}", uv_strerror(init_result));
            ctx->tun_poll->mark_uninit();
            return false;
        }

        int start_result = uv_poll_start(ctx->tun_poll->raw(), UV_READABLE, tun_poll_callback);
        if (start_result < 0) {
            errlog(ctx->logger, "configure: failed to start TUN poll: {}", uv_strerror(start_result));
            return false;
        }
    }

    ctx->timer = dns::Uv<uv_timer_t>::create_with_parent(ctx);
    int init_result = uv_timer_init(loop, ctx->timer->raw());
    if (init_result < 0) {
        errlog(ctx->logger, "init: failed to init timer: {}", uv_strerror(init_result));
        ctx->timer->mark_uninit();
        return false;
    }

    int start_result = uv_timer_start(ctx->timer->raw(), timer_callback, TIMER_PERIOD_S * 1000, TIMER_PERIOD_S * 1000);
    if (start_result < 0) {
        errlog(ctx->logger, "configure: failed to start timer: {}", uv_strerror(start_result));
        return false;
    }

    tracelog(ctx->logger, "configure: OK");
    return true;
}

static void release_resources(TcpipCtx *ctx) {
    delete ctx->pool;

    if (ctx->parameters.tun_fd != -1) {
        close(ctx->parameters.tun_fd);
    }
    if (ctx->pcap_fd != -1) {
        close(ctx->pcap_fd);
    }

    free(ctx->tun_input_buffer);

    delete ctx;
}

static void clean_up_events(TcpipCtx *ctx) {
    ctx->tun_poll.reset();
    ctx->timer.reset();
}

TcpipCtx *tcpip_init_internal(const TcpipParameters *params) {
    auto *ctx = new(std::nothrow) TcpipCtx{};
    if (nullptr == ctx) {
        errlog(ctx->logger, "init: no memory for operation");
        return nullptr;
    }

    ctx->parameters = *params;
    ctx->parameters.mtu_size = (0 == ctx->parameters.mtu_size) ? DEFAULT_MTU_SIZE : ctx->parameters.mtu_size;
    if (ctx->parameters.tun_fd != -1) {
        ctx->pool = new PacketPool(DEFAULT_PACKET_POOL_SIZE, ctx->parameters.mtu_size);
    }
    if (!configure_events(ctx)) {
        errlog(ctx->logger, "init: failed to create events");
        goto error;
    }

    ctx->tun_input_buffer = (uint8_t *) malloc(ctx->parameters.mtu_size);
    static_assert(std::is_trivial_v<netif>);
    ctx->netif = (netif *) calloc(1, sizeof(struct netif));
    if ((nullptr == ctx->tun_input_buffer) || (nullptr == ctx->netif)) {
        errlog(ctx->logger, "init: no memory for operation");
        goto error;
    }

    if (libuv_lwip_init(ctx) != ERR_OK) {
        errlog(ctx->logger, "lwip init failed");
        goto error;
    }

    netif_add_noaddr(ctx->netif, ctx, &netif_init_cb, netif_input);
    netif_set_default(ctx->netif);
    netif_set_up(ctx->netif);

    // Zeroes in `netif::ip_addr` break routing: anything but `ip_addr_any` should do.
    ctx->netif->ip_addr = IPADDR4_INIT_BYTES(1, 2, 3, 4);

    if (!tcp_cm_init(ctx) || !udp_cm_init(ctx) || !icmp_rm_init(ctx)) {
        goto error;
    }

    open_pcap_file(ctx, params->pcap_filename);

    return ctx;

error:
    tcpip_close_internal(ctx);
    return nullptr;
}

static void release_lwip_resources(TcpipCtx *ctx) {
    netif_remove(ctx->netif);
    free(ctx->netif);
    libuv_lwip_free();
}

void tcpip_close_internal(TcpipCtx *ctx) {
    tcp_cm_close(ctx);
    udp_cm_close(ctx);
    icmp_rm_close(ctx);

    release_lwip_resources(ctx);
    clean_up_events(ctx);
    release_resources(ctx);
}

void tcpip_refresh_connection_timeout(TcpipCtx *ctx, TcpipConnection *connection) {
    tcpip_refresh_connection_timeout_with_interval(ctx, connection, TCPIP_DEFAULT_CONNECTION_TIMEOUT_S);
}

void tcpip_refresh_connection_timeout_with_interval(TcpipCtx *ctx, TcpipConnection *connection, time_t seconds) {
    auto current_time = ctx->parameters.event_loop->now();

    timeval timeout_interval{};
    timeout_interval.tv_sec = seconds ? seconds : TCPIP_DEFAULT_CONNECTION_TIMEOUT_S;
    timeout_interval.tv_usec = 0;

    timeradd(&current_time, &timeout_interval, &connection->conn_timeout);
}

static void dump_packet_to_pcap(TcpipCtx *ctx, const uint8_t *data, size_t len) {
    auto tv = ctx->parameters.event_loop->now();
    if (pcap_write_packet(ctx->pcap_fd, &tv, data, len) < 0) {
        dbglog(ctx->logger, "pcap: failed to write packet to file");
        close(ctx->pcap_fd);
        ctx->pcap_fd = -1;
    }
}

static void dump_packet_iovec_to_pcap(TcpipCtx *ctx, std::span<uv_buf_t> chunks) {
    auto tv = ctx->parameters.event_loop->now();
    if (pcap_write_packet_uv_buf(ctx->pcap_fd, &tv, chunks.data(), chunks.size()) < 0) {
        dbglog(ctx->logger, "pcap: failed to write packet to file");
        close(ctx->pcap_fd);
        ctx->pcap_fd = -1;
    }
}

static void open_pcap_file(TcpipCtx *ctx, const char *pcap_filename) {
    if (pcap_filename == nullptr) {
        ctx->pcap_fd = -1;
        return;
    }

#ifdef _WIN32
    int flags = O_WRONLY | O_CREAT | O_TRUNC | O_BINARY;
    ctx->pcap_fd = _wopen(ag::utils::to_wstring(pcap_filename).c_str(), flags, 0664);
#else
    int flags = O_WRONLY | O_CREAT | O_TRUNC;
    ctx->pcap_fd = open(pcap_filename, flags, 0664);
#endif
    if (ctx->pcap_fd == -1) {
        errlog(ctx->logger, "pcap: can't open output file: {}", strerror(errno));
        return;
    }

    if (pcap_write_header(ctx->pcap_fd) < 0) {
        errlog(ctx->logger, "pcap: failed to write file header: {}", strerror(errno));
        close(ctx->pcap_fd);
        ctx->pcap_fd = -1;
        return;
    }

    infolog(ctx->logger, "started pcap capture");
}

void tcpip_process_input_packets(TcpipCtx *ctx, Packets *packets) {
    tracelog(ctx->logger, "TUN: processing {} input packets", packets->size);

    for (size_t i = 0; i < packets->size; ++i) {
        tracelog(ctx->logger, "TUN: packet length {}", packets->data[i].size);
        process_input_packet(ctx, &packets->data[i]);
    }

    tracelog(ctx->logger, "TUN: processed {} input packets", packets->size);
}

TcpipConnection *tcpip_get_connection_by_id(const ConnectionTables *tables, uint64_t id) {
    TcpipConnection *conn = nullptr;

    khiter_t iter = kh_get(connections_by_id, tables->by_id, id);
    if (iter != kh_end(tables->by_id)) {
        conn = kh_value(tables->by_id, iter);
    }

    return conn;
}

uint64_t lwip_ip_addr_hash(const ip_addr_t *addr) {
    sa_family_t family; // NOLINT(cppcoreguidelines-init-variables)
    const void *ip;     // NOLINT(cppcoreguidelines-init-variables)
    if (IP_IS_V4(addr)) {
        family = AF_INET;
        ip = &ip_2_ip4(addr)->addr;
    } else {
        family = AF_INET6;
        ip = ip_2_ip6(addr)->addr;
    }
    return ip_addr_hash(family, ip);
}

uint64_t addr_pair_hash(const AddressPair *addr) {
    uint64_t src_hash = hash_pair_combine(lwip_ip_addr_hash(&addr->src_ip), addr->src_port);
    uint64_t dst_hash = hash_pair_combine(lwip_ip_addr_hash(&addr->dst_ip), addr->dst_port);
    return hash_pair_combine(src_hash, dst_hash);
}

bool addr_pair_equals(const AddressPair *lh, const AddressPair *rh) {
    return lh->src_port == rh->src_port && lh->dst_port == rh->dst_port && ip_addr_cmp(&lh->src_ip, &rh->src_ip)
            && ip_addr_cmp(&lh->dst_ip, &rh->dst_ip);
}

TcpipConnection *tcpip_get_connection_by_ip(const ConnectionTables *tables, const ip_addr_t *src_addr,
        uint16_t src_port, const ip_addr_t *dst_addr, uint16_t dst_port) {
    TcpipConnection *conn = nullptr;

    AddressPair key = {*src_addr, src_port, *dst_addr, dst_port};

    khiter_t iter = kh_get(connections_by_addr, tables->by_addr, &key);
    if (iter != kh_end(tables->by_addr)) {
        conn = kh_value(tables->by_addr, iter);
    }

    return conn;
}

int tcpip_put_connection(ConnectionTables *tables, TcpipConnection *connection) {
    int r;
    khiter_t iter = kh_put(connections_by_id, tables->by_id, connection->id, &r);
    if (r < 0) {
        return 0;
    }
    kh_value(tables->by_id, iter) = connection;

    iter = kh_put(connections_by_addr, tables->by_addr, &connection->addr, &r);
    if (r < 0) {
        kh_del(connections_by_id, tables->by_id, connection->id);
        return 0;
    }
    kh_value(tables->by_addr, iter) = connection;

    return 1;
}

void tcpip_remove_connection(ConnectionTables *tables, TcpipConnection *connection) {
    khiter_t iter = kh_get(connections_by_id, tables->by_id, connection->id);
    if (iter != kh_end(tables->by_id)) {
        kh_del(connections_by_id, tables->by_id, iter);
    }

    iter = kh_get(connections_by_addr, tables->by_addr, &connection->addr);
    if (iter != kh_end(tables->by_addr)) {
        kh_del(connections_by_addr, tables->by_addr, iter);
    }
}

} // namespace ag
