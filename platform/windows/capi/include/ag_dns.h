#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef _WIN32
#  define AG_EXPORT extern __declspec(dllexport)
#elif defined(__GNUC__)
#  define AG_EXPORT __attribute__ ((visibility("default")))
#else
#  define AG_EXPORT
#endif

#define ARRAY_OF(T) struct { T *data; uint32_t size; }

#ifdef __cplusplus
extern "C" {
#endif

//
// Public types
//

typedef enum {
    AGLL_TRACE,
    AGLL_DEBUG,
    AGLL_INFO,
    AGLL_WARN,
    AGLL_ERR,
} ag_log_level;

typedef ARRAY_OF(uint8_t) ag_buffer;

typedef struct {
    /**
     * Server address, one of the following kinds:
     *     8.8.8.8:53 -- plain DNS (must specify IP address, not hostname)
     *     tcp://8.8.8.8:53 -- plain DNS over TCP (must specify IP address, not hostname)
     *     tls://dns.adguard.com -- DNS-over-TLS
     *     https://dns.adguard.com/dns-query -- DNS-over-HTTPS
     *     sdns://... -- DNS stamp (see https://dnscrypt.info/stamps-specifications)
     *     quic://dns.adguard.com:8853 -- DNS-over-QUIC
     */
    const char *address;

    /** List of plain DNS servers to be used to resolve the hostname in upstreams's address. */
    ARRAY_OF(const char *) bootstrap;

    /** Timeout, 0 means "default" */
    uint32_t timeout_ms;

    /** Upstream's IP address. If specified, the bootstrapper is NOT used. */
    ag_buffer resolved_ip_address;

    /** User-provided ID for this upstream */
    int32_t id;

    /** Index of the network interface to route traffic through, 0 is default */
    uint32_t outbound_interface_index;
} ag_upstream_options;

typedef struct {
    /** The upstreams to use for discovery of DNS64 prefixes (usually the system DNS servers) */
    ARRAY_OF(ag_upstream_options) upstreams;

    /** How many times, at most, to try DNS64 prefixes discovery before giving up */
    uint32_t max_tries;

    /** How long to wait before a dns64 prefixes discovery attempt */
    uint32_t wait_time_ms;
} ag_dns64_settings;

typedef enum {
    AGLP_UDP,
    AGLP_TCP
} ag_listener_protocol;

typedef enum {
    /** AdBlock-style filters -> REFUSED, hosts-style filters -> rule-specified or unspecified address */
    AGBM_DEFAULT,

    /** Always return NXDOMAIN */
    AGBM_REFUSED,

    /** Always return NXDOMAIN */
    AGBM_NXDOMAIN,

    /** Always return unspecified address */
    AGBM_UNSPECIFIED_ADDRESS,

    /** Always return custom configured IP address */
    AGBM_CUSTOM_ADDRESS,
} ag_dnsproxy_blocking_mode;

typedef struct {
    /** The address to listen on */
    const char *address;

    /** The port to listen on */
    uint16_t port;

    /** The protocol to listen for */
    ag_listener_protocol protocol;

    /** If true, don't close the TCP connection after sending the first response */
    bool persistent;

    /** Close the TCP connection this long after the last request received */
    uint32_t idle_timeout_ms;
} ag_listener_settings;

typedef enum {
    /** Plain HTTP proxy */
    AGOPP_HTTP_CONNECT,

    /** HTTPs proxy */
    AGOPP_HTTPS_CONNECT,

    /** Socks4 proxy */
    AGOPP_SOCKS4,

    /** Socks5 proxy without UDP support */
    AGOPP_SOCKS5,

    /** Socks5 proxy with UDP support */
    AGOPP_SOCKS5_UDP,
} ag_outbound_proxy_protocol;

typedef struct {
    const char *username;
    const char *password;
} ag_outbound_proxy_auth_info;

typedef struct {
    /** The proxy protocol */
    ag_outbound_proxy_protocol protocol;

    /** The proxy server address (must be a valid IP address) */
    const char *address;

    /** The proxy server port */
    uint16_t port;

    /** The authentication information */
    ag_outbound_proxy_auth_info *auth_info;

    /** If true and the proxy connection is secure, the certificate won't be verified */
    bool trust_any_certificate;
} ag_outbound_proxy_settings;

typedef struct {
    /** Filter ID */
    int32_t id;
    /** Path to the filter list file or string with rules, depending on value of in_memory */
    const char *data;
    /** If true, data is rules, otherwise data is path to file with rules */
    bool in_memory;
} ag_filter_params;

typedef struct {
    ARRAY_OF(ag_filter_params) filters;
} ag_filter_engine_params;

typedef struct {
    /** List of upstreams */
    ARRAY_OF(ag_upstream_options) upstreams;
    /** List of fallback upstreams, which will be used if none of the usual upstreams respond */
    ARRAY_OF(ag_upstream_options) fallbacks;
    /**
     * Requests for these domains will be forwarded directly to the fallback upstreams, if there are any.
     * A wildcard character, `*`, which stands for any number of characters, is allowed to appear multiple
     * times anywhere except at the end of the domain (which implies that a domain consisting only of
     * wildcard characters is invalid).
     */
    ARRAY_OF(const char *) fallback_domains;
    /** (Optional) DNS64 prefix discovery settings */
    ag_dns64_settings *dns64;
    /** TTL of a blocking response */
    uint32_t blocked_response_ttl_secs;
    /** Filtering engine parameters */
    ag_filter_engine_params filter_params;
    /** List of listener parameters */
    ARRAY_OF(ag_listener_settings) listeners;
    /** Outbound proxy settings */
    ag_outbound_proxy_settings *outbound_proxy;
    /** If true, all AAAA requests will be blocked */
    bool block_ipv6;
    /** If true, the bootstrappers are allowed to fetch AAAA records */
    bool ipv6_available;
    /** How to respond to filtered requests */
    ag_dnsproxy_blocking_mode blocking_mode;
    /** Custom IPv4 address to return for filtered requests */
    const char *custom_blocking_ipv4;
    /** Custom IPv6 address to return for filtered requests */
    const char *custom_blocking_ipv6;
    /** Maximum number of cached responses (may be 0) */
    uint32_t dns_cache_size;
    /** Enable optimistic DNS caching */
    bool optimistic_cache;
    /**
     * Enable DNSSEC OK extension.
     * This options tells server that we want to receive DNSSEC records along with normal queries.
     * If they exist, request processed event will have DNSSEC flag on.
     * WARNING: may increase data usage and probability of TCP fallbacks.
     */
    bool enable_dnssec_ok;
    /** If enabled, detect retransmitted requests and handle them using fallback upstreams only */
    bool enable_retransmission_handling;
} ag_dnsproxy_settings;

typedef struct {
    /** Queried domain name */
    const char *domain;
    /** Query type */
    const char *type;
    /** Processing start time, in milliseconds since UNIX epoch */
    int64_t start_time;
    /** Time spent on processing */
    int32_t elapsed;
    /** DNS reply status */
    const char *status;
    /** A string representation of the DNS reply sent */
    const char *answer;
    /** A string representation of the original upstream's DNS reply (present when blocked by CNAME) */
    const char *original_answer;
    /** ID of the upstream that provided this answer */
    const int32_t *upstream_id;
    /** Number of bytes sent to the upstream */
    int32_t bytes_sent;
    /** Number of bytes received from the upstream */
    int32_t bytes_received;
    /** List of matched rules (full rule text) */
    ARRAY_OF(const char *) rules;
    /** Corresponding filter ID for each matched rule */
    ARRAY_OF(const int32_t) filter_list_ids;
    /** True if the matched rule is a whitelist rule */
    bool whitelist;
    /** If not NULL, contains the error description */
    const char *error;
    /** True if this response was served from the cache */
    bool cache_hit;
    /** True if this response has DNSSEC rrsig */
    bool dnssec;
} ag_dns_request_processed_event;

typedef struct {
    /** Leaf certificate */
    ag_buffer certificate;
    /** Certificate chain */
    ARRAY_OF(ag_buffer) chain;
} ag_certificate_verification_event;

/** Called synchronously right after a request has been processed, but before a response is returned. */
typedef void (*ag_dns_request_processed_cb)(const ag_dns_request_processed_event *);

typedef enum {
    AGCVR_OK,

    AGCVR_ERROR_CREATE_CERT,
    AGCVR_ERROR_ACCESS_TO_STORE,
    AGCVR_ERROR_CERT_VERIFICATION,

    AGCVR_COUNT
} ag_certificate_verification_result;

/** Called synchronously when a certificate needs to be verified */
typedef ag_certificate_verification_result (*ag_certificate_verification_cb)(const ag_certificate_verification_event *);

/** Called when we need to log a message */
typedef void (*ag_log_cb)(void *attachment, const char *name, ag_log_level level, const char *message);

typedef struct {
    ag_dns_request_processed_cb on_request_processed;
    ag_certificate_verification_cb on_certificate_verification;
} ag_dnsproxy_events;

typedef enum {
    AGSPT_PLAIN,
    AGSPT_DNSCRYPT,
    AGSPT_DOH,
    AGSPT_TLS,
    AGSPT_DOQ,
} ag_stamp_proto_type;

typedef enum {
    /** Resolver does DNSSEC validation */
    AGSIP_DNSSEC = 1 << 0,
    /** Resolver does not record logs */
    AGSIP_NO_LOG = 1 << 1,
    /** Resolver doesn't intentionally block domains */
    AGSIP_NO_FILTER = 1 << 2,
} ag_server_informal_properties;

typedef struct {
    /** Protocol */
    ag_stamp_proto_type proto;
    /** IP address and/or port */
    const char *server_addr;
    /**
     * Provider means different things depending on the stamp type
     * DNSCrypt: the DNSCrypt provider name
     * DOH and DOT: server's hostname
     * Plain DNS: not specified
     */
    const char *provider_name;
    /** (For DoH) absolute URI path, such as /dns-query */
    const char *path;
    /** The DNSCrypt provider’s Ed25519 public key, as 32 raw bytes. Empty for other types. */
    ag_buffer server_public_key;
    /**
     * Hash is the SHA256 digest of one of the TBS certificate found in the validation chain, typically
     * the certificate used to sign the resolver’s certificate. Multiple hashes can be provided for seamless
     * rotations.
     */
    ARRAY_OF(ag_buffer) hashes;
    /** Server properties */
    ag_server_informal_properties properties;
} ag_dns_stamp;


//
// API functions
//

typedef void ag_dnsproxy;

/**
 * Initialize and start a proxy.
 * @return a proxy handle, or
 *         NULL in case of an error
 */
AG_EXPORT ag_dnsproxy *ag_dnsproxy_init(const ag_dnsproxy_settings *settings, const ag_dnsproxy_events *events);

/**
 * Stop and destroy a proxy.
 * @param proxy a proxy handle
 */
AG_EXPORT void ag_dnsproxy_deinit(ag_dnsproxy *proxy);

/**
 * Process a DNS message and return the response.
 * The caller is responsible for freeing both buffers with `ag_buffer_free()`.
 * @param message a DNS request in wire format
 * @return a DNS response in wire format
 */
AG_EXPORT ag_buffer ag_dnsproxy_handle_message(ag_dnsproxy *proxy, ag_buffer message);

/**
 * Return the current proxy settings. The caller is responsible for freeing
 * the returned pointer with `ag_dnsproxy_settings_free()`.
 * @return the current proxy settings
 */
AG_EXPORT ag_dnsproxy_settings *ag_dnsproxy_get_settings(ag_dnsproxy *proxy);

/**
 * Return the default proxy settings. The caller is responsible for freeing
 * the returned pointer with `ag_dnsproxy_settings_free()`.
 * @return the default proxy settings
 */
AG_EXPORT ag_dnsproxy_settings *ag_dnsproxy_settings_get_default();

/**
 * Free a dnsproxy_settings pointer.
 */
AG_EXPORT void ag_dnsproxy_settings_free(ag_dnsproxy_settings *settings);

/**
 * Free a buffer.
 */
AG_EXPORT void ag_buffer_free(ag_buffer buf);

/**
 * Set the log verbosity level.
 */
AG_EXPORT void ag_set_default_log_level(ag_log_level level);

/**
 * Set the logging function.
 * @param attachment an argument to the logging function
 */
AG_EXPORT void ag_logger_set_default_callback(ag_log_cb callback, void *attachment);

/**
 * Parse a DNS stamp string. The caller is responsible for freeing
 * the result with `ag_parse_dns_stamp_result_free()`.
 * @param stamp_str "sdns://..." string
 * @param error on output, if an error occurred, contains the error description (free with `ag_str_free()`)
 * @return a parsed stamp, or NULL if an error occurred.
 */
AG_EXPORT ag_dns_stamp *ag_dns_stamp_from_str(const char *stamp_str, const char **error);

/**
 * Free a ag_parse_dns_stamp_result pointer.
 */
AG_EXPORT void ag_dns_stamp_free(ag_dns_stamp *stamp);

/**
 * Convert a DNS stamp to "sdns://..." string.
 * Free the string with `ag_str_free()`
 */
AG_EXPORT const char *ag_dns_stamp_to_str(ag_dns_stamp *stamp);

/**
 * Convert a DNS stamp to string that can be used as an upstream URL.
 * Free the string with `ag_str_free()`
 */
AG_EXPORT const char *ag_dns_stamp_pretty_url(ag_dns_stamp *stamp);

/**
 * Convert a DNS stamp to string that can NOT be used as an upstream URL, but may be prettier.
 * Free the string with `ag_str_free()`
 */
AG_EXPORT const char *ag_dns_stamp_prettier_url(ag_dns_stamp *stamp);

/**
 * Check if an upstream is valid and working.
 * The caller is responsible for freeing the result with `ag_str_free()`.
 * @return NULL if everything is ok, or
 *         an error message.
 */
AG_EXPORT const char *ag_test_upstream(const ag_upstream_options *upstream,
                                       ag_certificate_verification_cb on_certificate_verification);

/**
 * Return the C API version (hash of this file).
 */
AG_EXPORT const char *ag_get_capi_version();

/**
 * Return the DNS proxy library version.
 * Do NOT free the returned string.
 */
AG_EXPORT const char *ag_dnsproxy_version();

/**
 * Free a string.
 */
AG_EXPORT void ag_str_free(const char *str);

#ifdef _WIN32
/**
 * Disable the SetUnhandledExceptionFilter function.
 */
AG_EXPORT void ag_disable_SetUnhandledExceptionFilter(void);

/**
 * Enable the SetUnhandledExceptionFilter function.
 */
AG_EXPORT void ag_enable_SetUnhandledExceptionFilter(void);
#endif

#ifdef __cplusplus
} // extern "C"
#endif
