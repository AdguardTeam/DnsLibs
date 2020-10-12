#pragma once


#include <ag_logger.h>
#include <ag_defs.h>
#include <ag_utils.h>
#include <ag_socket_address.h>
#include <upstream.h>
#include "bootstrapper.h"
#include "event_loop.h"

#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_openssl.h>

#include <ldns/ldns.h>
#include <event2/event.h>
#include <event2/buffer.h>

#include <random>
#include <set>
#include <deque>
#include <unordered_map>
#include <condition_variable>
#include <list>

using namespace std::chrono;

namespace ag {

class dns_over_quic : public upstream {
public:

    /**
     * @param opts upstream settings
     * @param config factory configuration
     */
    dns_over_quic(const upstream_options &opts, const upstream_factory_config &config);
    ~dns_over_quic() override;

    static int set_encryption_secrets(SSL *ssl, enum ssl_encryption_level_t ossl_level,
                                      const uint8_t *read_secret,
                                      const uint8_t *write_secret, size_t secret_len);

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

        size_t size() const { return tail - buf.data(); }
        size_t left() const { return buf.data() + buf.size() - tail; }
        uint8_t *const wpos() { return tail; }
        const uint8_t *rpos() const { return buf.data(); }
        void push(size_t len) { tail += len; }
        void reset() { tail = buf.data(); }

        std::vector<uint8_t> buf;
        uint8_t *tail;
    };
    struct stream {
        int64_t stream_id = -1; // actually not used
        int64_t request_id = 0;
        std::vector<uint8_t> raw_data;
        struct {
            std::unique_ptr<evbuffer, ag::ftor<&evbuffer_free>> buf;
            int read_position = 0;
        } send_info;
    };
    struct crypto {
        std::deque<buffer> data;
    };
    struct request_t {
        int64_t request_id = -1;
        ag::ldns_pkt_ptr reply_pkt;
        ag::ldns_buffer_ptr request_buffer;
        std::condition_variable cond;
        bool is_onfly{false};
    };
    struct socket_state {
        evutil_socket_t fd{-1};
        bool connected{false};
    };

    err_string init() override;
    exchange_result exchange(ldns_pkt *) override;

    static int recv_crypto_data(ngtcp2_conn *conn, ngtcp2_crypto_level crypto_level,
                                uint64_t offset, const uint8_t *data, size_t datalen,
                                void *user_data);

    static int update_key(ngtcp2_conn *conn, uint8_t *rx_secret, uint8_t *tx_secret,
                          ngtcp2_crypto_aead_ctx *rx_aead_ctx, uint8_t *rx_iv,
                          ngtcp2_crypto_aead_ctx *tx_aead_ctx, uint8_t *tx_iv,
                          const uint8_t *current_rx_secret,
                          const uint8_t *current_tx_secret, size_t secretlen,
                          void *user_data);

    static int recv_stream_data(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id,
                                uint64_t offset, const uint8_t *data, size_t datalen,
                                void *user_data, void *stream_user_data);

    static int get_new_connection_id(ngtcp2_conn *conn, ngtcp2_cid *cid,
                                     uint8_t *token, size_t cidlen, void *user_data);

    static int on_close_stream(ngtcp2_conn *conn, int64_t stream_id,
                               uint64_t app_error_code, void *user_data,
                               void *stream_user_data);

    static int acked_stream_data_offset(ngtcp2_conn *conn, int64_t stream_id,
                                        uint64_t offset, uint64_t datalen, void *user_data,
                                        void *stream_user_data);

    static int handshake_confirmed(ngtcp2_conn *, void *data);
    static int ssl_verify_callback(X509_STORE_CTX *ctx, void *arg);

    static void read_cb(int, short, void *data);
    static void idle_timer_cb(int, short, void *data);
    static void retransmit_cb(int, short, void *data);

    int init_ssl_ctx();
    int init_ssl();
    evutil_socket_t create_dual_stack_socket();
    evutil_socket_t create_ipv4_socket();
    int bind_addr(int fd, int family);
    int on_read();
    int on_read_connected();
    int on_read_not_connected();
    int on_write();
    int write_streams();
    int send_packet();
    int send_packet_connected();
    int send_packet_not_connected();
    int reinit();
    int handle_expiry();
    void ag_ngtcp2_settings_default(ngtcp2_settings &settings);
    int feed_data(const ngtcp2_pkt_info *pi, uint8_t *data, size_t datalen);
    void submit(std::function<void()> &&func) const;
    void send_requests();
    void process_reply(int64_t request_id, const uint8_t *request_data, size_t request_data_len);
    void deinit();
    void disconnect(std::string_view reason);
    void schedule_retransmit();
    ngtcp2_tstamp get_tstamp() const;
    ngtcp2_crypto_level from_ossl_level(enum ssl_encryption_level_t ossl_level) const;
    void disqualify_server_address(const ag::socket_address &server_address);
    void update_idle_timer(bool reset);

    void write_client_handshake(ngtcp2_crypto_level level, const uint8_t *data, size_t datalen);
    int on_key(ngtcp2_crypto_level level, const uint8_t *rx_secret,
               const uint8_t *tx_secret, size_t secretlen);

    socket_state m_sock_state;
    std::atomic<state> m_state{STOP};
    std::string m_server_name;
    int m_port{0};
    logger m_log = create_logger("DOQ upstream");
    bootstrapper_ptr m_bootstrapper;
    milliseconds m_request_timer;
    ag::socket_address m_remote_addr_empty, m_local_addr;
    std::deque<ag::socket_address> m_server_addresses;
    std::vector<ag::socket_address> m_current_addresses;
    ngtcp2_conn_callbacks m_callbacks;
    size_t m_max_pktlen;
    uint32_t m_version;
    buffer m_send_buf;
    SSL_CTX *m_ssl_ctx{nullptr};
    SSL *m_ssl{nullptr};
    ngtcp2_conn *m_conn{nullptr};
    crypto m_crypto[3];
    std::list<int64_t> m_stream_send_queue;
    std::unordered_map<int64_t, stream> m_streams;
    std::unordered_map<int64_t, request_t> m_requests;
    std::mutex m_global;
    event_loop_ptr m_loop = event_loop::create();
    struct event *m_read_event{nullptr};
    struct event *m_idle_timer_event{nullptr};
    struct event *m_retransmit_timer_event{nullptr};
    static std::atomic_int64_t m_next_request_id;
    static std::array<uint8_t, 32> m_static_secret;
};

} // ag
