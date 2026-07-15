#pragma once

// In-process DNSCrypt responder bound to 127.0.0.1. It performs the full
// DNSCrypt handshake (provider keypair, certificate generation/signing, TXT
// cert distribution, encrypted-relay decrypt/encrypt) so the DNSCrypt client
// can be exercised offline against a local server instead of real public
// DNSCrypt resolvers.
//
// Crypto is reused, never reimplemented: the on-wire certificate is laid out
// byte-for-byte as the client parser (dns_crypt_server_info.cpp) expects, the
// AEAD relays go through the cipher_* wrappers (dns_crypt_cipher.h), and the
// Ed25519 provider + X25519 resolver keypairs use libsodium directly. UDP/TCP
// socket + DNS framing reuse the detail:: helpers from loopback_dns_server.h.

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <functional>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include <ldns/ldns.h>
#include <sodium.h>

#include <gtest/gtest.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#endif

#include "common/net_utils.h"
#include "common/utils.h"
#include "dns/common/dns_defs.h"
#include "dns/dnscrypt/dns_crypt_cipher.h"
#include "dns/dnscrypt/dns_crypt_consts.h"
#include "dns/dnscrypt/dns_crypt_utils.h"
#include "dns/dnsstamp/dns_stamp.h"

#include "loopback_dns_server.h" // detail:: socket helpers + build_dns_reply

namespace ag::test::detail {

// DNSCrypt wire constants — mirror dns_crypt_server_info.cpp byte-for-byte.
inline constexpr uint8_t CERT_MAGIC[]{0x44, 0x4e, 0x53, 0x43}; // "DNSC"
inline constexpr uint8_t SERVER_MAGIC[]{0x72, 0x36, 0x66, 0x6e, 0x76, 0x57, 0x6a, 0x38};

// On-wire encrypted-certificate layout (124 bytes total). The client parses
// exactly these offsets in ServerInfo::txt_to_cert_info.
inline constexpr size_t CERT_MAGIC_OFFSET = 0;
inline constexpr size_t ES_VERSION_OFFSET = 4;     // uint16_t, network order
inline constexpr size_t PROTOCOL_MINOR_OFFSET = 6; // uint16_t
inline constexpr size_t SIGNATURE_OFFSET = 8;      // 64-byte Ed25519 signature
inline constexpr size_t RESOLVER_PK_OFFSET = 72;   // 32-byte X25519 resolver public key
inline constexpr size_t CLIENT_MAGIC_OFFSET = 104; // 8-byte client magic
inline constexpr size_t SERIAL_OFFSET = 112;       // uint32_t, network order
inline constexpr size_t TS_START_OFFSET = 116;     // uint32_t, network order
inline constexpr size_t TS_END_OFFSET = 120;       // uint32_t, network order
inline constexpr size_t CERT_SIZE = 124;
inline constexpr size_t SIGNATURE_SIZE = RESOLVER_PK_OFFSET - SIGNATURE_OFFSET; // 64
inline constexpr size_t SIGNED_REGION_SIZE = CERT_SIZE - RESOLVER_PK_OFFSET;    // 52
inline constexpr size_t MIN_DNSCRYPT_PACKET_SIZE = 12 + 5; // matches ServerInfo::MIN_DNS_PACKET_SIZE

// Cert validity window: returns (not_before, not_after) bracketing "now".
inline std::pair<uint32_t, uint32_t> cert_validity_window() {
    auto now = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch())
                       .count();
    return {static_cast<uint32_t>(now) - 3600, static_cast<uint32_t>(now) + 31536000};
}

// PKCS7 padding for DNSCrypt relays. These call the exact same libsodium
// primitives (sodium_pad/sodium_unpad, with the block size equal to the total
// padded length) as the dnscrypt library's pad()/unpad() in
// dns_crypt_padding.cpp, so the wire bytes are bit-compatible with the client
// side. Inlined here so the header stays self-contained without depending on
// the dnscrypt module's private padding header.
inline bool pad_pkt(ag::Uint8Vector &packet, size_t min_size) {
    size_t unpadded_buflen = packet.size();
    packet.resize(min_size);
    return 0 == ::sodium_pad(nullptr, packet.data(), unpadded_buflen, packet.size(), packet.size());
}

inline bool unpad_pkt(ag::Uint8Vector &packet) {
    size_t unpadded_buflen = 0;
    if (0 != ::sodium_unpad(&unpadded_buflen, packet.data(), packet.size(), packet.size())) {
        return false;
    }
    packet.resize(unpadded_buflen);
    return true;
}

} // namespace ag::test::detail

namespace ag::test {

class LoopbackDnscryptServer {
public:
    using Handler = detail::DnsReplyHandler;

    explicit LoopbackDnscryptServer(Handler handler,
            ag::dns::dnscrypt::CryptoConstruction algo = ag::dns::dnscrypt::CryptoConstruction::X_SALSA_20_POLY_1305,
            bool tcp = true, bool udp = true)
            : m_handler(std::move(handler))
            , m_algo(algo)
            , m_tcp(tcp)
            , m_udp(udp) {
    }

    ~LoopbackDnscryptServer() {
        stop();
    }

    LoopbackDnscryptServer(const LoopbackDnscryptServer &) = delete;
    LoopbackDnscryptServer &operator=(const LoopbackDnscryptServer &) = delete;

    // Binds 127.0.0.1:0 (UDP + TCP share one ephemeral port), generates the
    // provider/resolver keypairs + signed cert, and starts the worker
    // thread(s). Blocks until the ephemeral port is assigned, so stamp() /
    // address() / port() are usable on return.
    // Fail-fast: any socket()/bind()/listen() failure (or a port that resolves
    // to 0) records a test failure via ADD_FAILURE (not ASSERT_*: those expand to
    // `co_return` and would turn this void method into a coroutine), resets the
    // partially-opened sockets, and returns without starting any worker thread
    // or flipping m_running — so stop()/destruction never join a non-existent
    // thread. Mirrors the defensive pattern in LoopbackTlsServer::start().
    void start() {
        if (m_running.load()) {
            return;
        }
        detail::ensure_winsock();
        init_keys();

        if (m_udp) {
            m_udp_sock = detail::open_dgram_socket();
            if (m_udp_sock == detail::invalid_socket()) {
                ADD_FAILURE() << "LoopbackDnscryptServer: UDP socket() failed";
                reset_start_state();
                return;
            }
            sockaddr_in addr{};
            addr.sin_family = AF_INET;
            addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            addr.sin_port = 0;
            if (::bind(m_udp_sock, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) != 0) {
                ADD_FAILURE() << "LoopbackDnscryptServer: UDP bind() failed";
                reset_start_state();
                return;
            }
            m_port = detail::get_port(m_udp_sock);
            if (m_port == 0) {
                ADD_FAILURE() << "LoopbackDnscryptServer: UDP bound port resolved to 0";
                reset_start_state();
                return;
            }
        }

        if (m_tcp) {
            m_tcp_sock = detail::open_stream_socket();
            if (m_tcp_sock == detail::invalid_socket()) {
                ADD_FAILURE() << "LoopbackDnscryptServer: TCP socket() failed";
                reset_start_state();
                return;
            }
            detail::set_reuseaddr(m_tcp_sock);
            sockaddr_in addr{};
            addr.sin_family = AF_INET;
            addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            addr.sin_port = htons(m_port);
            if (::bind(m_tcp_sock, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) != 0) {
                ADD_FAILURE() << "LoopbackDnscryptServer: TCP bind() failed";
                reset_start_state();
                return;
            }
            if (m_port == 0) {
                m_port = detail::get_port(m_tcp_sock);
            }
            if (::listen(m_tcp_sock, SOMAXCONN) != 0) {
                ADD_FAILURE() << "LoopbackDnscryptServer: TCP listen() failed";
                reset_start_state();
                return;
            }
            if (m_port == 0) {
                ADD_FAILURE() << "LoopbackDnscryptServer: TCP bound port resolved to 0";
                reset_start_state();
                return;
            }
        }

        // All socket setup succeeded: flip m_running and start the worker
        // thread(s) only now, so a setup failure never leaves the server running
        // on an invalid/unbound socket (and never leaves one transport running
        // while the other failed).
        m_running.store(true);
        if (m_udp) {
            m_udp_thread = std::thread([this] {
                udp_loop();
            });
        }
        if (m_tcp) {
            m_tcp_thread = std::thread([this] {
                tcp_loop();
            });
        }
    }

    // Stops the worker thread(s) and closes the socket(s). Idempotent.
    void stop() {
        if (!m_running.exchange(false)) {
            return;
        }
        detail::shutdown_socket(m_udp_sock);
        detail::shutdown_socket(m_tcp_sock);
        detail::close_fd(m_udp_sock);
        detail::close_fd(m_tcp_sock);
        m_udp_sock = detail::invalid_socket();
        m_tcp_sock = detail::invalid_socket();
        if (m_udp_thread.joinable()) {
            m_udp_thread.join();
        }
        if (m_tcp_thread.joinable()) {
            m_tcp_thread.join();
        }
    }

    // "sdns://..." encoding of 127.0.0.1:<port> + provider Ed25519 public key
    // + provider name, parseable by the existing dnscrypt::Client::dial path.
    std::string stamp() const {
        ag::dns::ServerStamp s;
        s.proto = ag::dns::StampProtoType::DNSCRYPT;
        // props must be set or ServerStamp::str() falls back to pretty_url().
        s.set_server_properties(ag::dns::ServerInformalProperties{});
        s.server_addr_str = AG_FMT("127.0.0.1:{}", m_port);
        s.server_pk.assign(m_provider_pk.begin(), m_provider_pk.end());
        s.provider_name = m_provider_name;
        return s.str();
    }

    // "<scheme>://127.0.0.1:<port>" — the plain upstream address (mostly for
    // diagnostics; the client dials via stamp()).
    std::string address(ag::utils::TransportProtocol proto) const {
        const char *scheme = (proto == ag::utils::TP_TCP) ? "tcp" : "udp";
        return AG_FMT("{}://127.0.0.1:{}", scheme, m_port);
    }

    uint16_t port() const {
        return m_port;
    }

private:
    // Closes any sockets opened by start() and resets port bookkeeping. Used
    // only by start()'s fail-fast branches so the server is never left
    // half-initialized (one transport up, the other down). Idempotent: closing
    // an invalid_socket() is a no-op.
    void reset_start_state() {
        detail::close_fd(m_udp_sock);
        detail::close_fd(m_tcp_sock);
        m_udp_sock = detail::invalid_socket();
        m_tcp_sock = detail::invalid_socket();
        m_port = 0;
    }

    // Generates the Ed25519 provider keypair (signs the cert; its public key
    // goes into the stamp), the X25519 resolver keypair (ECDH for relays;
    // its public key goes into the cert), the client magic, and the signed
    // serialized cert blob.
    void init_keys() {
        (void) ::sodium_init();
        if (::crypto_sign_keypair(m_provider_pk.data(), m_provider_sk.data()) != 0
                || ::crypto_box_keypair(m_resolver_pk.data(), m_resolver_sk.data()) != 0) {
            return;
        }
        ::randombytes_buf(m_magic_query.data(), m_magic_query.size());
        m_serial = 1;
        auto [not_before, not_after] = detail::cert_validity_window();
        m_not_before = not_before;
        m_not_after = not_after;
        m_cert = serialize_cert();
    }

    // Serializes the DNSCrypt cert blob (124 bytes) with the Ed25519 provider
    // signature over the resolver-pk..ts_end region. Matches the layout parsed
    // by ServerInfo::txt_to_cert_info.
    std::vector<uint8_t> serialize_cert() const {
        std::vector<uint8_t> cert(detail::CERT_SIZE, 0);
        std::memcpy(&cert[detail::CERT_MAGIC_OFFSET], detail::CERT_MAGIC, std::size(detail::CERT_MAGIC));
        const uint16_t es_version = htons(static_cast<uint16_t>(m_algo));
        std::memcpy(&cert[detail::ES_VERSION_OFFSET], &es_version, sizeof(es_version));
        const uint16_t protocol_minor = htons(1);
        std::memcpy(&cert[detail::PROTOCOL_MINOR_OFFSET], &protocol_minor, sizeof(protocol_minor));
        // Signed region [RESOLVER_PK_OFFSET, CERT_SIZE): resolver pk + client
        // magic + serial + ts_start + ts_end.
        std::memcpy(&cert[detail::RESOLVER_PK_OFFSET], m_resolver_pk.data(), m_resolver_pk.size());
        std::memcpy(&cert[detail::CLIENT_MAGIC_OFFSET], m_magic_query.data(), m_magic_query.size());
        const uint32_t serial = htonl(m_serial);
        std::memcpy(&cert[detail::SERIAL_OFFSET], &serial, sizeof(serial));
        const uint32_t not_before = htonl(m_not_before);
        std::memcpy(&cert[detail::TS_START_OFFSET], &not_before, sizeof(not_before));
        const uint32_t not_after = htonl(m_not_after);
        std::memcpy(&cert[detail::TS_END_OFFSET], &not_after, sizeof(not_after));
        // Ed25519 signature over the signed region, written to [SIGNATURE_OFFSET, RESOLVER_PK_OFFSET).
        (void) ::crypto_sign_detached(&cert[detail::SIGNATURE_OFFSET], nullptr, &cert[detail::RESOLVER_PK_OFFSET],
                detail::SIGNED_REGION_SIZE, m_provider_sk.data());
        return cert;
    }

    // Dispatches an incoming wire payload. DNSCrypt relays are recognised by
    // the server's client-magic prefix; everything else is treated as a plain
    // DNS query (the cert-fetch TXT query, or any query routed to the handler).
    std::optional<std::vector<uint8_t>> handle_packet(const uint8_t *data, size_t len) {
        if (len >= ag::dns::dnscrypt::CLIENT_MAGIC_LEN && m_magic_query.size() == ag::dns::dnscrypt::CLIENT_MAGIC_LEN
                && std::equal(m_magic_query.begin(), m_magic_query.end(), data)) {
            return handle_relay(data, len);
        }
        return handle_plain_dns(data, len);
    }

    // Builds the TXT reply serving the serialized cert (cert-fetch query).
    static void push_cert_txt_rr(ldns_pkt *reply, const ldns_rr *question, const std::vector<uint8_t> &cert) {
        ldns_rr *txt_rr = ldns_rr_new();
        ldns_rr_set_type(txt_rr, LDNS_RR_TYPE_TXT);
        ldns_rr_set_class(txt_rr, LDNS_RR_CLASS_IN);
        ldns_rr_set_owner(txt_rr, ldns_rdf_clone(ldns_rr_owner(question)));
        ldns_rr_set_ttl(txt_rr, 0);
        // TXT character-string = [1-byte length][cert bytes]. ldns stores an
        // LDNS_RDF_TYPE_STR as the raw [length][data] bytes, which the client
        // reads back skipping the leading length byte (txt_to_cert_info).
        std::vector<uint8_t> rdata;
        rdata.reserve(cert.size() + 1);
        rdata.push_back(static_cast<uint8_t>(cert.size()));
        rdata.insert(rdata.end(), cert.begin(), cert.end());
        ldns_rdf *rdf = ldns_rdf_new_frm_data(LDNS_RDF_TYPE_STR, rdata.size(), rdata.data());
        if (rdf != nullptr) {
            ldns_rr_push_rdf(txt_rr, rdf);
        }
        ldns_pkt_push_rr(reply, LDNS_SECTION_ANSWER, txt_rr);
    }

    // Handles a plaintext DNS packet: a TXT query is answered with the cert;
    // any other query is forwarded to the user-supplied handler.
    std::optional<std::vector<uint8_t>> handle_plain_dns(const uint8_t *data, size_t len) const {
        ldns_pkt *request_raw = nullptr;
        if (ldns_wire2pkt(&request_raw, data, len) != LDNS_STATUS_OK || request_raw == nullptr) {
            if (request_raw != nullptr) {
                ldns_pkt_free(request_raw);
            }
            return std::nullopt;
        }
        ag::dns::ldns_pkt_ptr request{request_raw};
        const ldns_rr *question = ldns_rr_list_rr(ldns_pkt_question(request.get()), 0);
        if (question != nullptr && ldns_rr_get_type(question) == LDNS_RR_TYPE_TXT) {
            ag::dns::ldns_pkt_ptr reply{ldns_pkt_clone(request.get())};
            ldns_pkt_set_qr(reply.get(), true);
            ldns_pkt_set_ra(reply.get(), true);
            ldns_pkt_set_rcode(reply.get(), LDNS_RCODE_NOERROR);
            push_cert_txt_rr(reply.get(), question, m_cert);
            return serialize_pkt(*reply);
        }
        return detail::build_dns_reply(m_handler, data, len);
    }

    // Decrypts a DNSCrypt relay, runs the handler on the inner query, and
    // re-encrypts the reply. Mirrors ServerInfo::encrypt/decrypt with the
    // server-side resolver keys.
    std::optional<std::vector<uint8_t>> handle_relay(const uint8_t *data, size_t len) const {
        namespace dc = ag::dns::dnscrypt;
        // Relay = client_magic(8) || client_pk(32) || client_nonce(12) || ciphertext.
        // The AEAD tag is appended to the ciphertext by the client's cipher_seal,
        // so the prefix before the ciphertext holds no tag bytes.
        const size_t prefix = dc::CLIENT_MAGIC_LEN + dc::KEY_SIZE + dc::HALF_NONCE_SIZE;
        if (len < prefix + dc::TAG_SIZE + detail::MIN_DNSCRYPT_PACKET_SIZE) {
            return std::nullopt;
        }
        // Client public key (X25519) + half nonce extracted from the relay.
        dc::KeyArray client_pk{};
        std::memcpy(client_pk.data(), data + dc::CLIENT_MAGIC_LEN, dc::KEY_SIZE);
        std::array<uint8_t, dc::HALF_NONCE_SIZE> client_nonce{};
        std::memcpy(client_nonce.data(), data + dc::CLIENT_MAGIC_LEN + dc::KEY_SIZE, dc::HALF_NONCE_SIZE);
        // Full nonce = client_nonce (12) || zeros (12), matching ServerInfo::encrypt.
        dc::nonce_array nonce{};
        std::copy(client_nonce.begin(), client_nonce.end(), nonce.begin());
        const uint8_t *ciphertext = data + prefix;
        const size_t ciphertext_len = len - prefix;

        auto shared_res = dc::cipher_shared_key(m_algo, m_resolver_sk, client_pk);
        if (shared_res.has_error()) {
            return std::nullopt;
        }
        const dc::KeyArray &shared_key = shared_res.value();
        auto open_res = dc::cipher_open(m_algo, ag::Uint8View(ciphertext, ciphertext_len), nonce, shared_key);
        if (open_res.has_error()) {
            return std::nullopt;
        }
        ag::Uint8Vector plain = std::move(open_res.value());
        if (!detail::unpad_pkt(plain) || plain.size() < detail::MIN_DNSCRYPT_PACKET_SIZE) {
            return std::nullopt;
        }
        // Inner query -> handler -> wire reply.
        auto inner_reply = detail::build_dns_reply(m_handler, plain.data(), plain.size());
        if (!inner_reply) {
            return std::nullopt;
        }
        // Pad the reply to a multiple of 64 bytes strictly larger than the
        // reply (so sodium_pad has room for at least one padding byte).
        ag::Uint8Vector reply_vec(inner_reply->begin(), inner_reply->end());
        size_t padded_len = std::min(ag::dns::dnscrypt::MAX_DNS_UDP_SAFE_PACKET_SIZE,
                ((reply_vec.size() + 1) + 63) & ~static_cast<size_t>(63));
        if (!detail::pad_pkt(reply_vec, padded_len)) {
            return std::nullopt;
        }
        // Reply nonce = client_nonce (12) || server-random (12); the client
        // checks the first half matches its own client nonce.
        dc::nonce_array server_nonce{};
        std::copy(client_nonce.begin(), client_nonce.end(), server_nonce.begin());
        ::randombytes_buf(server_nonce.data() + dc::HALF_NONCE_SIZE, dc::HALF_NONCE_SIZE);
        auto seal_res = dc::cipher_seal(m_algo, ag::as_u8v(reply_vec), server_nonce, shared_key);
        if (seal_res.has_error()) {
            return std::nullopt;
        }
        // Reply = SERVER_MAGIC || server_nonce || ciphertext.
        std::vector<uint8_t> out;
        out.reserve(std::size(detail::SERVER_MAGIC) + server_nonce.size() + seal_res->size());
        out.insert(out.end(), std::begin(detail::SERVER_MAGIC), std::end(detail::SERVER_MAGIC));
        out.insert(out.end(), server_nonce.begin(), server_nonce.end());
        out.insert(out.end(), seal_res->begin(), seal_res->end());
        return out;
    }

    // Serializes an ldns packet to wire bytes.
    static std::optional<std::vector<uint8_t>> serialize_pkt(const ldns_pkt &pkt) {
        ag::dns::ldns_buffer_ptr buffer{ldns_buffer_new(detail::MAX_DNS_PACKET)};
        if (buffer == nullptr) {
            return std::nullopt;
        }
        if (ldns_pkt2buffer_wire(buffer.get(), &pkt) != LDNS_STATUS_OK) {
            return std::nullopt;
        }
        const uint8_t *begin = ldns_buffer_begin(buffer.get());
        const size_t size = ldns_buffer_position(buffer.get());
        return std::vector<uint8_t>(begin, begin + size);
    }

    void udp_loop() {
        std::vector<uint8_t> buf(detail::MAX_DNS_PACKET);
        while (m_running.load()) {
            sockaddr_in client{};
            detail::socklen_type client_len = sizeof(client);
#ifdef _WIN32
            int n = ::recvfrom(m_udp_sock, reinterpret_cast<char *>(buf.data()), static_cast<int>(buf.size()), 0,
                    reinterpret_cast<sockaddr *>(&client), &client_len);
#else
            ssize_t n = ::recvfrom(
                    m_udp_sock, buf.data(), buf.size(), 0, reinterpret_cast<sockaddr *>(&client), &client_len);
#endif
            if (n <= 0) {
                break;
            }
            auto reply = handle_packet(buf.data(), static_cast<size_t>(n));
            if (reply) {
#ifdef _WIN32
                (void) ::sendto(m_udp_sock, reinterpret_cast<const char *>(reply->data()),
                        static_cast<int>(reply->size()), 0, reinterpret_cast<sockaddr *>(&client), client_len);
#else
                (void) ::sendto(
                        m_udp_sock, reply->data(), reply->size(), 0, reinterpret_cast<sockaddr *>(&client), client_len);
#endif
            }
        }
    }

    // One query per accepted connection: 2-byte length prefix, payload, reply
    // (length-prefixed), then close. Same deadlock-safe model as
    // LoopbackDnsServer::tcp_loop.
    void tcp_loop() {
        std::vector<uint8_t> buf;
        while (m_running.load()) {
            sockaddr_in client{};
            detail::socklen_type client_len = sizeof(client);
            detail::socket_type conn = ::accept(m_tcp_sock, reinterpret_cast<sockaddr *>(&client), &client_len);
            if (conn == detail::invalid_socket()) {
                break;
            }
            uint16_t len_net = 0;
            bool ok = detail::recv_exact(conn, reinterpret_cast<uint8_t *>(&len_net), 2);
            uint16_t msg_len = ok ? ntohs(len_net) : 0;
            if (!ok || msg_len == 0) {
                detail::close_fd(conn);
                continue;
            }
            buf.resize(msg_len);
            if (!detail::recv_exact(conn, buf.data(), msg_len)) {
                detail::close_fd(conn);
                continue;
            }
            auto reply = handle_packet(buf.data(), msg_len);
            if (reply) {
                uint16_t rlen_net = htons(static_cast<uint16_t>(reply->size()));
                (void) detail::send_exact(conn, reinterpret_cast<uint8_t *>(&rlen_net), 2);
                (void) detail::send_exact(conn, reply->data(), reply->size());
            }
            detail::close_fd(conn);
        }
    }

    Handler m_handler;
    ag::dns::dnscrypt::CryptoConstruction m_algo;
    bool m_tcp;
    bool m_udp;

    std::array<uint8_t, crypto_sign_PUBLICKEYBYTES> m_provider_pk{}; // Ed25519 (stamp -> cert sig verify)
    std::array<uint8_t, crypto_sign_SECRETKEYBYTES> m_provider_sk{}; // Ed25519 (signs cert)
    ag::dns::dnscrypt::KeyArray m_resolver_pk{};                     // X25519 (in cert, ECDH peer)
    ag::dns::dnscrypt::KeyArray m_resolver_sk{};                     // X25519 (ECDH local secret)
    ag::dns::dnscrypt::ClientMagicArray m_magic_query{};
    uint32_t m_serial{0};
    uint32_t m_not_before{0};
    uint32_t m_not_after{0};
    std::vector<uint8_t> m_cert;
    // Provider name as it appears in the stamp (no trailing dot; the client
    // appends one before the TXT cert-fetch query).
    std::string m_provider_name = "2.dnscrypt-cert.loopback.test";

    uint16_t m_port{0};
    std::atomic_bool m_running{false};
    detail::socket_type m_udp_sock{detail::invalid_socket()};
    detail::socket_type m_tcp_sock{detail::invalid_socket()};
    std::thread m_udp_thread;
    std::thread m_tcp_thread;
};

} // namespace ag::test
