#include "dns/proxy/tun_listener.h"

#include <memory>

#include "common/coro.h"
#include "common/logger.h"
#include "common/net_utils.h"
#include "common/socket_address.h"
#include "tcpip/tcpip.h"
#include "tcpip/utils.h"
#include "tcp_dns_payload_parser.h"
#include "dns/common/dns_utils.h"
#include "dns/common/event_loop.h"

namespace ag::dns {

// Connection state tracking
struct TunConnection {
    uint64_t id;
    utils::TransportProtocol proto;
    SocketAddress src;
    SocketAddress dst;
    std::shared_ptr<bool> guard;
    TcpDnsPayloadParser parser; // Only used for TCP
};

struct TunListener::Impl {
    Logger log{"TunListener"};
    EventLoopPtr loop;
    int fd{-1};
    int mtu{0};
    TunListener::RequestCallback request_callback;
    TunListener::OutputCallback output_callback; // Only used in external mode
    TcpipCtx *tcpip_ctx{nullptr}; // Only used in autonomous mode
    HashMap<uint64_t, TunConnection> connections;
    std::shared_ptr<bool> shutdown_guard;

    static void tcpip_event_handler(void *arg, TcpipEvent event_id, void *event_data) {
        auto *self = (Impl *) arg;

        switch (event_id) {
        case TCPIP_EVENT_GENERATE_CONN_ID: {
            auto *id_ptr = (uint64_t *) event_data;
            static std::atomic<uint64_t> id_counter{0};
            *id_ptr = ++id_counter;
            break;
        }
        case TCPIP_EVENT_CONNECT_REQUEST: {
            auto *req = (TcpipConnectRequestEvent *) event_data;
            self->on_connect_request(req);
            break;
        }
        case TCPIP_EVENT_CONNECTION_ACCEPTED: {
            uint64_t id = *(uint64_t *) event_data;
            self->on_connection_accepted(id);
            break;
        }
        case TCPIP_EVENT_READ: {
            auto *read_event = (TcpipReadEvent *) event_data;
            self->on_read(read_event);
            break;
        }
        case TCPIP_EVENT_CONNECTION_CLOSED: {
            uint64_t id = *(uint64_t *) event_data;
            self->on_connection_closed(id);
            break;
        }
        case TCPIP_EVENT_TUN_OUTPUT: {
            auto *output_event = (TcpipTunOutputEvent *) event_data;
            self->on_tun_output(output_event);
            break;
        }
        case TCPIP_EVENT_DATA_SENT:
        case TCPIP_EVENT_STAT_NOTIFY:
        case TCPIP_EVENT_ICMP_ECHO:
            // Not used
            break;
        }
    }

    void on_connect_request(TcpipConnectRequestEvent *req) {
        dbglog(log, "[{}] Connect request: proto={}, {}:{} -> {}:{}",
                req->id, req->proto,
                req->src->host_str(), req->src->port(),
                req->dst->host_str(), req->dst->port());

        // Accept all DNS connections (port 53)
        if (req->dst->port() == 53) {
            // Store connection info
            TunConnection conn;
            conn.id = req->id;
            conn.proto = (req->proto == IPPROTO_TCP) ? utils::TP_TCP : utils::TP_UDP;
            conn.src = *req->src;
            conn.dst = *req->dst;
            conn.guard = shutdown_guard;
            connections[req->id] = conn;

            tcpip_complete_connect_request(tcpip_ctx, req->id, TCPIP_ACT_BYPASS);
        } else {
            // Reject non-DNS traffic
            tcpip_complete_connect_request(tcpip_ctx, req->id, TCPIP_ACT_REJECT);
        }
    }

    void on_connection_accepted(uint64_t id) {
        dbglog(log, "[{}] Connection accepted", id);
    }

    void on_read(TcpipReadEvent *read_event) {
        if (read_event->datalen == 0 || read_event->data == nullptr) {
            read_event->result = 0;
            return;
        }

        auto it = connections.find(read_event->id);
        if (it == connections.end()) {
            warnlog(log, "[{}] Read from unknown connection", read_event->id);
            read_event->result = -1;
            return;
        }

        // Concatenate all buffers
        Uint8Vector data;
        for (size_t i = 0; i < read_event->datalen; ++i) {
            const auto &buf = read_event->data[i];
            data.insert(data.end(), (uint8_t *) buf.base, (uint8_t *) buf.base + buf.len);
        }

        size_t total_consumed = data.size();

        if (it->second.proto == utils::TP_TCP) {
            // TCP: parse length-prefixed messages
            it->second.parser.push_data({data.data(), data.size()});

            Uint8Vector payload;
            while (it->second.parser.next_payload(payload)) {
                dbglog(log, "[{}] Parsed {} bytes from TCP connection", read_event->id, payload.size());

                // Process request asynchronously (callback may block)
                coro::run_detached(process_request(read_event->id, std::move(payload), it->second.proto));
            }
        } else {
            // UDP: entire datagram is the payload
            dbglog(log, "[{}] Read {} bytes from UDP connection", read_event->id, data.size());

            coro::run_detached(process_request(read_event->id, std::move(data), it->second.proto));
        }

        read_event->result = total_consumed;

        // Notify tcpip that we've consumed the data
        tcpip_sent_to_remote(tcpip_ctx, read_event->id, total_consumed);
    }

    void process_response(uint64_t conn_id, utils::TransportProtocol proto, Uint8Vector reply) {
        if (reply.empty()) {
            return;
        }

        if (proto == utils::TP_TCP) {
            // TCP: add length prefix
            uint16_t length_prefix = htons(reply.size());
            Uint8Vector tcp_response;
            tcp_response.reserve(reply.size() + sizeof(length_prefix));
            tcp_response.insert(tcp_response.end(),
                    (uint8_t *) &length_prefix,
                    (uint8_t *) &length_prefix + sizeof(length_prefix));
            tcp_response.insert(tcp_response.end(), reply.begin(), reply.end());

            dbglog(log, "[{}] Sending {} bytes response (+ 2 byte length prefix)", conn_id, reply.size());
            int sent = tcpip_send_to_client(tcpip_ctx, conn_id, tcp_response.data(), tcp_response.size());
            if (sent < 0) {
                warnlog(log, "[{}] Failed to send response", conn_id);
            }
        } else {
            dbglog(log, "[{}] Sending {} bytes response", conn_id, reply.size());
            int sent = tcpip_send_to_client(tcpip_ctx, conn_id, reply.data(), reply.size());
            if (sent < 0) {
                warnlog(log, "[{}] Failed to send response", conn_id);
            }
        }
    }

    coro::Task<void> process_request(uint64_t conn_id, Uint8Vector request_data, utils::TransportProtocol proto) {
        std::weak_ptr<bool> guard = shutdown_guard;

        // Create completion callback
        // Note: completion is captured by value in request_callback, which allows
        // the user callback to invoke it asynchronously (after this coroutine returns).
        // The reply data must be copied by completion before this function is used.
        auto completion = [this, conn_id, proto, guard](Uint8View reply) {
            if (guard.expired()) {
                return;
            }

            Uint8Vector reply_copy(reply.begin(), reply.end());
            loop->submit([this, conn_id, proto, reply_copy = std::move(reply_copy), guard]() {
                if (guard.expired()) {
                    return;
                }
                process_response(conn_id, proto, std::move(reply_copy));
            });
        };

        // Call user callback
        request_callback(Uint8View{request_data.data(), request_data.size()}, std::move(completion));

        co_return;
    }

    void on_connection_closed(uint64_t id) {
        dbglog(log, "[{}] Connection closed", id);
        connections.erase(id);
    }

    void on_tun_output(TcpipTunOutputEvent *event) {
        if (fd != -1 || !output_callback) {
            return;
        }

        Uint8Vector packet;

        // Concatenate all chunks into single packet
        for (size_t i = 0; i < event->packet.chunks_num; ++i) {
            const auto &chunk = event->packet.chunks[i];
            packet.insert(packet.end(), (uint8_t *) chunk.base, (uint8_t *) chunk.base + chunk.len);
        }

        dbglog(log, "Sending {} bytes to TUN device (family={})", packet.size(), event->family);
        output_callback(Uint8View{packet.data(), packet.size()});
    }
};

TunListener::TunListener()
    : m_pimpl(new TunListener::Impl) {
}

TunListener::~TunListener() = default;

Error<TunListener::InitError> TunListener::init(
        int fd, int mtu, RequestCallback request_callback, OutputCallback output_callback) {
    std::unique_ptr<Impl> &tun_listener = m_pimpl;

    if (mtu < 0) {
        errlog(tun_listener->log, "Invalid MTU: {}", mtu);
        return make_error(InitError::IE_INVALID_MTU);
    }

    if (!request_callback) {
        errlog(tun_listener->log, "Request callback is null");
        return make_error(InitError::IE_INVALID_CALLBACK);
    }

    tun_listener->fd = fd;
    tun_listener->mtu = mtu == 0 ? DEFAULT_MTU_SIZE : mtu;
    tun_listener->request_callback = std::move(request_callback);
    tun_listener->shutdown_guard = std::make_shared<bool>(true);

    // External mode (fd == -1)
    if (tun_listener->fd == -1) {
        if (!output_callback) {
            errlog(tun_listener->log, "Output callback is required for external mode");
            return make_error(InitError::IE_INVALID_CALLBACK);
        }
        tun_listener->output_callback = std::move(output_callback);
    }

    tun_listener->loop = EventLoop::create();

    // Initialize tcpip stack BEFORE starting event loop
    TcpipParameters params{};
    params.tun_fd = tun_listener->fd;  // -1 for external mode, >= 0 for autonomous mode
    params.event_loop = tun_listener->loop.get();
    params.mtu_size = tun_listener->mtu == 0 ? DEFAULT_MTU_SIZE : (uint32_t) tun_listener->mtu;
    params.pcap_filename = nullptr;
    params.handler.handler = Impl::tcpip_event_handler;
    params.handler.arg = tun_listener.get();

    tun_listener->tcpip_ctx = tcpip_open(&params);
    if (!tun_listener->tcpip_ctx) {
        errlog(tun_listener->log, "Failed to initialize tcpip stack");
        return make_error(InitError::IE_TCPIP_INIT_FAILED);
    }

    // Start event loop AFTER tcpip is initialized
    tun_listener->loop->start({
#if defined(__APPLE__) && TARGET_OS_IPHONE
            .qos_class = QOS_CLASS_DEFAULT,
            .qos_relative_priority = 0
#endif // __APPLE__ && TARGET_OS_IPHONE
    });

    if (tun_listener->fd == -1) {
        infolog(tun_listener->log, "TunListener initialized in external mode (mtu={})", tun_listener->mtu);
    } else {
        infolog(tun_listener->log, "TunListener initialized in autonomous mode (fd={}, mtu={})",
                tun_listener->fd, tun_listener->mtu);
    }

    return {};
}

void TunListener::deinit() {
    std::unique_ptr<Impl> &tun_listener = m_pimpl;
    if (tun_listener->loop == nullptr) {
        infolog(tun_listener->log, "TunListener module is not initialized, deinitialization is not needed");
        tun_listener->shutdown_guard.reset();
        tun_listener->fd = -1;
        tun_listener->mtu = 0;
        tun_listener->request_callback = {};
        tun_listener->output_callback = {};
        return;
    }
    tun_listener->loop->start();
    tun_listener->loop->submit([this] {
        std::unique_ptr<Impl> &tun_listener = m_pimpl;
        infolog(tun_listener->log, "Deinitializing TunListener module...");

        tun_listener->connections.clear();

        if (tun_listener->tcpip_ctx) {
            tcpip_close(tun_listener->tcpip_ctx);
            tun_listener->tcpip_ctx = nullptr;
        }

        infolog(tun_listener->log, "Stopping event loop");
        tun_listener->loop->stop();
        infolog(tun_listener->log, "Stopping event loop done");
    });
    infolog(tun_listener->log, "Joining event loop");
    tun_listener->loop->join();
    infolog(tun_listener->log, "Joining event loop done");
    infolog(tun_listener->log, "TunListener module deinitialized");

    tun_listener->shutdown_guard.reset();
    tun_listener->fd = -1;
    tun_listener->mtu = 0;
    tun_listener->request_callback = {};
    tun_listener->output_callback = {};

    infolog(tun_listener->log, "TunListener deinitialized");
}

void TunListener::handle_packets(Packets packets) {
    std::unique_ptr<Impl> &tun_listener = m_pimpl;

    auto packets_holder = std::make_shared<PacketsHolder>(packets);

    if (tun_listener->fd != -1) {
        errlog(tun_listener->log, "non-external mode (fd={})", tun_listener->fd);
        return;
    }

    if (!tun_listener->loop || !tun_listener->tcpip_ctx) {
        errlog(tun_listener->log, "uninitialized listener");
        return;
    }

    tun_listener->loop->submit([this, packets_holder]() {
        auto packets = packets_holder->release();
        process_packets({packets.data(), (uint32_t) packets.size()});
    });
}

void TunListener::process_packets(Packets packets) {
    std::unique_ptr<Impl> &tun_listener = m_pimpl;
    tcpip_tun_input(tun_listener->tcpip_ctx, &packets);
}

} // namespace ag::dns
