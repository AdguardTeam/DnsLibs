#pragma once


#include "common/logger.h"
#include "common/defs.h"
#include "common/utils.h"
#include "common/socket_address.h"
#include <ag_event_loop.h>
#include <ag_socket.h>
#include <upstream.h>
#include "bootstrapper.h"

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
#include "tls_session_cache.h"

using namespace std::chrono;

namespace ag {

class dns_over_quic : public upstream {
public:
    static constexpr auto DEFAULT_PORT = 853;
    static constexpr std::string_view SCHEME = "quic://";

    /**
     * @param opts upstream settings
     * @param config factory configuration
     */
    dns_over_quic(const upstream_options &opts, const upstream_factory_config &config);
    ~dns_over_quic() override;

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
    enum network_error {
        NETWORK_ERR_HANDSHAKE_RUN = 1,
        NETWORK_ERR_OK = 0,
        NETWORK_ERR_FATAL = -10,
        NETWORK_ERR_SEND_BLOCKED = -11,
        NETWORK_ERR_CLOSE_WAIT = -12,
        NETWORK_ERR_RETRY = -13,
        NETWORK_ERR_DROP_CONN = -14
    };
    enum state {
        STOP = 0,
        HANDSHAKE,
        RUN
    };
    struct buffer {
        buffer(const uint8_t *data, size_t datalen);
        explicit buffer(size_t datalen);

        size_t size() const { return tail; }
        size_t left() const { return buf.size() - tail; }
        uint8_t *wpos() { return buf.data() + tail; }
        const uint8_t *rpos() const { return buf.data(); }
        void push(size_t len) { tail += len; }
        void reset() { tail = 0; }

        std::vector<uint8_t> buf;
        size_t tail;
    };
    struct stream {
        int64_t stream_id = -1; // actually not used
        int64_t request_id = 0;
        std::vector<uint8_t> raw_data;
        struct {
            UniquePtr<evbuffer, &evbuffer_free> buf;
            int read_position = 0;
        } send_info;
    };
    struct crypto {
        std::deque<buffer> data;
    };
    struct request_t {
        int64_t request_id = -1;
        ngtcp2_tstamp starting_time{0};
        ag::ldns_pkt_ptr reply_pkt;
        ag::ldns_buffer_ptr request_buffer;
        std::condition_variable cond;
        bool is_onfly{false};
    };
    struct socket_context {
        dns_over_quic *upstream = nullptr;
        socket_factory::socket_ptr socket;
    };
    struct connection_handshake_initial_info {
        std::vector<std::unique_ptr<socket_context>> sockets;
        socket_context *last_connected_socket = nullptr;
    };
    struct connection_state {
        using state_info_variant = std::variant<
                /** Idle */
                std::monostate,
                /** Before a peer is selected */
                connection_handshake_initial_info,
                /** A peer has been selected */
                std::unique_ptr<socket_context>>;

        state_info_variant info;

        [[nodiscard]] bool is_peer_selected() const;
        std::unique_ptr<socket_context> extract_socket(socket_context *ctx);
    };

    ErrString init() override;
    exchange_result exchange(ldns_pkt *, const dns_message_info *info) override;

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

    static int on_close_stream(ngtcp2_conn *conn, int64_t stream_id,
                               uint64_t app_error_code, void *user_data,
                               void *stream_user_data);

    static int acked_stream_data_offset(ngtcp2_conn *conn, int64_t stream_id,
                                        uint64_t offset, uint64_t datalen, void *user_data,
                                        void *stream_user_data);

    static int handshake_confirmed(ngtcp2_conn *, void *data);
    static int ssl_verify_callback(X509_STORE_CTX *ctx, void *arg);

    static void idle_timer_cb(evutil_socket_t, short, void *data);
    static void handshake_timer_cb(evutil_socket_t, short, void *data);
    static void retransmit_cb(evutil_socket_t, short, void *data);

    static void on_socket_connected(void *arg);
    static void on_socket_read(void *arg, Uint8View data);
    static void on_socket_close(void *arg, std::optional<socket::error> error);

    int init_quic_conn(const socket *connected_socket);
    int init_ssl_ctx();
    int init_ssl();
    int on_write();
    int write_streams();
    int send_packet();
    int send_packet(socket *active_socket, Uint8View data);
    int reinit();
    int handle_expiry();
    void ag_ngtcp2_settings_default(ngtcp2_settings &settings, ngtcp2_transport_params &params) const;
    int feed_data(Uint8View data);
    void submit(std::function<void()> &&func) const;
    void send_requests();
    void process_reply(int64_t request_id, const uint8_t *request_data, size_t request_data_len);
    void disconnect(std::string_view reason);
    void schedule_retransmit();
    static ngtcp2_tstamp get_tstamp();
    ngtcp2_crypto_level from_ossl_level(enum ssl_encryption_level_t ossl_level) const;
    void disqualify_server_address(const ag::SocketAddress &server_address);
    void update_idle_timer(bool reset);

    void write_client_handshake(ngtcp2_crypto_level level, const uint8_t *data, size_t datalen);
    int on_key(ngtcp2_crypto_level level, const uint8_t *rx_secret,
               const uint8_t *tx_secret, size_t secretlen);

    int connect_to_peers(const std::vector<ag::SocketAddress> &current_addresses);

    connection_state m_conn_state;
    std::atomic<state> m_state{STOP};
    std::string m_server_name;
    int m_port{0};
    ag::Logger m_log{"DOQ upstream"};
    bootstrapper_ptr m_bootstrapper;
    ag::SocketAddress m_remote_addr_empty, m_local_addr;
    std::list<ag::SocketAddress> m_server_addresses;
    ngtcp2_callbacks m_callbacks{};
    size_t m_max_pktlen;
    uint32_t m_quic_version;
    buffer m_send_buf;
    bssl::UniquePtr<SSL_CTX> m_ssl_ctx;
    bssl::UniquePtr<SSL> m_ssl;
    ngtcp2_conn *m_conn{nullptr};
    crypto m_crypto[3];
    std::list<int64_t> m_stream_send_queue;
    std::unordered_map<int64_t, stream> m_streams;
    std::unordered_map<int64_t, request_t> m_requests;
    std::mutex m_global;
    event_loop_ptr m_loop = event_loop::create();
    UniquePtr<event, &event_free> m_read_event;
    UniquePtr<event, &event_free> m_idle_timer_event;
    UniquePtr<event, &event_free> m_handshake_timer_event;
    UniquePtr<event, &event_free> m_retransmit_timer_event;
    static std::atomic_int64_t m_next_request_id;
    std::array<uint8_t, 32> m_static_secret;
    tls_session_cache m_tls_session_cache;
};

} // ag
