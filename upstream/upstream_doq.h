#pragma once


#include "common/logger.h"
#include "common/defs.h"
#include "common/utils.h"
#include "common/socket_address.h"
#include "dns/common/event_loop.h"
#include "dns/net/socket.h"
#include "dns/upstream/upstream.h"
#include "dns/upstream/bootstrapper.h"

#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_boringssl.h>

#include <ldns/ldns.h>
#include <event2/event.h>
#include <event2/buffer.h>

#include <deque>
#include <unordered_map>
#include <condition_variable>
#include <list>
#include <variant>
#include "dns/net/tls_session_cache.h"

using namespace std::chrono;

namespace ag::dns {

class DoqUpstream : public Upstream {
public:
    static constexpr std::string_view RFC9250_ALPN = "doq";
    static constexpr std::string_view SCHEME = "quic://";

    /**
     * @param opts upstream settings
     * @param config factory configuration
     */
    DoqUpstream(const UpstreamOptions &opts, const UpstreamFactoryConfig &config);
    ~DoqUpstream() override;

#if BORINGSSL_API_VERSION < 10
    static int set_encryption_secrets(SSL *ssl, enum ssl_encryption_level_t ossl_level, const uint8_t *read_secret,
                                      const uint8_t *write_secret, size_t secret_len);
#else
    static int set_rx_secret(SSL *ssl, enum ssl_encryption_level_t ossl_level, const SSL_CIPHER *cipher,
                             const uint8_t *read_secret, size_t secret_len);
    static int set_tx_secret(SSL *ssl, enum ssl_encryption_level_t ossl_level, const SSL_CIPHER *cipher,
                             const uint8_t *write_secret, size_t secret_len);
#endif

    static int add_handshake_data(SSL *ssl, enum ssl_encryption_level_t ossl_level,
                                  const uint8_t *data, size_t len);

    static int flush_flight(SSL *ssl);
    static int send_alert(SSL *ssl, enum ssl_encryption_level_t level, uint8_t alert);

private:
    enum NetworkError {
        NETWORK_ERR_HANDSHAKE_RUN = 1,
        NETWORK_ERR_OK = 0,
        NETWORK_ERR_FATAL = -10,
        NETWORK_ERR_DROP_CONN = -14
    };
    enum State {
        STOP = 0,
        HANDSHAKE,
        RUN
    };
    struct Buffer {
        Buffer(const uint8_t *data, size_t datalen);
        explicit Buffer(size_t datalen);

        size_t size() const { return tail; }
        size_t left() const { return buf.size() - tail; }
        uint8_t *wpos() { return buf.data() + tail; }
        const uint8_t *rpos() const { return buf.data(); }
        void push(size_t len) { tail += len; }
        void reset() { tail = 0; }

        Uint8Vector buf;
        size_t tail;
    };
    struct Stream {
        int64_t request_id = 0;
        Uint8Vector raw_data;
        struct {
            UniquePtr<evbuffer, &evbuffer_free> buf;
            int read_position = 0;
        } send_info;
    };
    struct Crypto {
        std::deque<Buffer> data;
    };
    struct Request {
        int64_t request_id = -1;
        ldns_pkt_ptr reply_pkt;
        ldns_buffer_ptr request_buffer;
        bool completed = false;
        std::coroutine_handle<> caller{};
        bool is_onfly{false};
        Error<DnsError> error;

        void complete() {
            completed = true;
            if (caller) {
                std::exchange(caller, nullptr).resume();
            }
        }
        ~Request() {
            complete();
        }
    };
    struct SocketContext {
        DoqUpstream *upstream = nullptr;
        SocketFactory::SocketPtr socket;
    };
    struct ConnectionHandshakeInitialInfo {
        std::vector<std::unique_ptr<SocketContext>> sockets;
        SocketContext *last_connected_socket = nullptr;
    };
    struct ConnectionState {
        using StateInfoVariant = std::variant<
                /** Idle */
                std::monostate,
                /** Before a peer is selected */
                ConnectionHandshakeInitialInfo,
                /** A peer has been selected */
                std::unique_ptr<SocketContext>>;

        StateInfoVariant info;

        [[nodiscard]] bool is_peer_selected() const;
        std::unique_ptr<SocketContext> extract_socket(SocketContext *ctx);
    };

    Error<InitError> init() override;
    coro::Task<ExchangeResult> exchange(ldns_pkt *, const DnsMessageInfo *info) override;

    static int version_negotiation(ngtcp2_conn *conn, const ngtcp2_pkt_hd *hd,
        const uint32_t *sv, size_t nsv, void *user_data);

    static int recv_crypto_data(ngtcp2_conn *conn, ngtcp2_crypto_level crypto_level,
                                uint64_t offset, const uint8_t *data, size_t datalen,
                                void *user_data);

    static int recv_stream_data(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id,
                                uint64_t offset, const uint8_t *data, size_t datalen,
                                void *user_data, void *stream_user_data);

    static int get_new_connection_id(ngtcp2_conn *conn, ngtcp2_cid *cid,
                                     uint8_t *token, size_t cidlen, void *user_data);

    static int update_key(ngtcp2_conn *conn, uint8_t *rx_secret, uint8_t *tx_secret,
                          ngtcp2_crypto_aead_ctx *rx_aead_ctx, uint8_t *rx_iv,
                          ngtcp2_crypto_aead_ctx *tx_aead_ctx, uint8_t *tx_iv,
                          const uint8_t *current_rx_secret,
                          const uint8_t *current_tx_secret, size_t secretlen,
                          void *user_data);

    static int on_close_stream(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id,
                               uint64_t app_error_code, void *user_data,
                               void *stream_user_data);

    static int acked_stream_data_offset(ngtcp2_conn *conn, int64_t stream_id,
                                        uint64_t offset, uint64_t datalen, void *user_data,
                                        void *stream_user_data);

    static int handshake_confirmed(ngtcp2_conn *, void *data);
    static int ssl_verify_callback(X509_STORE_CTX *ctx, void *arg);

    static void short_timeout_timer_cb(uv_timer_t *timer);
    static void handshake_timer_cb(uv_timer_t *timer);
    static void retransmit_cb(uv_timer_t *timer);

    static void on_socket_connected(void *arg);
    static void on_socket_read(void *arg, Uint8View data);
    static void on_socket_close(void *arg, Error<SocketError> error);

    int init_quic_conn(const Socket *connected_socket);
    int init_ssl_ctx();
    int init_ssl();
    int on_write();
    int write_streams();
    int send_packet();
    int send_packet(Socket *active_socket, Uint8View data);
    int reinit();
    int handle_expiry();
    void ag_ngtcp2_settings_default(ngtcp2_settings &settings, ngtcp2_transport_params &params) const;
    int feed_data(Uint8View data);
    void send_requests();
    void process_reply(int64_t request_id, Uint8View reply);
    void disconnect(std::string_view reason);
    void schedule_retransmit();
    static ngtcp2_tstamp get_tstamp();
    ngtcp2_crypto_level from_ossl_level(enum ssl_encryption_level_t ossl_level) const;
    void disqualify_server_address(const ag::SocketAddress &server_address);
    void update_idle_timer(bool reset);

    void write_client_handshake(ngtcp2_crypto_level level, const uint8_t *data, size_t datalen);
    int on_key(ngtcp2_crypto_level level, const uint8_t *rx_secret,
               const uint8_t *tx_secret, size_t secretlen);
    static void on_rand(uint8_t *dest, size_t destlen, const ngtcp2_rand_ctx *rand_ctx);

    int connect_to_peers(const std::vector<ag::SocketAddress> &current_addresses);

    ConnectionState m_conn_state;
    std::atomic<State> m_state{STOP};
    std::string m_server_name;
    int m_port{0};
    ag::Logger m_log{"DOQ upstream"};
    BootstrapperPtr m_bootstrapper;
    ag::SocketAddress m_remote_addr_empty, m_local_addr;
    std::list<ag::SocketAddress> m_server_addresses;
    ngtcp2_callbacks m_callbacks{};
    size_t m_max_pktlen;
    uint32_t m_quic_version;
    Buffer m_send_buf;
    bssl::UniquePtr<SSL_CTX> m_ssl_ctx;
    bssl::UniquePtr<SSL> m_ssl;
    ngtcp2_conn *m_conn{nullptr};
    Crypto m_crypto[3];
    std::list<int64_t> m_stream_send_queue;
    std::unordered_map<int64_t, Stream> m_streams;
    std::unordered_map<int64_t, Request> m_requests;
    UvPtr<uv_timer_t> m_short_timeout_timer;
    UvPtr<uv_timer_t> m_handshake_timer;
    UvPtr<uv_timer_t> m_retransmit_timer;
    static std::atomic_int64_t m_next_request_id;
    std::array<uint8_t, 32> m_static_secret;
    TlsSessionCache m_tls_session_cache;
    Error<DnsError> m_fatal_error;
    std::shared_ptr<bool> m_shutdown_guard;
};

} // ag
