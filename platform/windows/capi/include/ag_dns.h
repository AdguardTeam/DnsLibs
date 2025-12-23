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

/**
 * @defgroup defines Defines
 */
/**
 * @defgroup enums Enumerations
 */

/** @def NAMED_ARRAY_OF(T, N)
 *  Defines a named array structure for a specific data type. It takes two arguments: the data type T and a name N.
 *  This macro creates a structure with the provided name N, containing a pointer to the data type T called data and
 *  a 32-bit unsigned integer called size representing the number of elements in the array. This macro can be used
 *  to create custom array structures with a specific name and data type for easier and more readable code.
 *
 *  @internal This type of macro is used to make the macro look better in the generated documentation.
 *  Usage example:
 *  @code{.c}
 *  struct Config {
 *      ARRAY_OF(ag_buffer, buffers_s) buffers;
 *  }
 *  @endcode
 *  @ingroup defines
 */
#define NAMED_ARRAY_OF(T, N) struct N { T *data; uint32_t size; }

/** @def ARRAY_OF(T)
 *  A macro that defines a typed array structure with a pointer to the data and its size.
 *
 *  Macro generates a structure containing a pointer to an array of type `T` and a `uint32_t` size variable.
 *  You can use it to create typed array structures for any data type.
 *
 *  Usage example:
 *  @code{.c}
 *  typedef ARRAY_OF(uint8_t) ag_buffer;
 *  @endcode
 *  @ingroup defines
 */
#define ARRAY_OF(T) struct { T *data; uint32_t size; }

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @ingroup enums
 * Log levels for the logging system.
 *
 * Aavailables log levels for the logging system.
 */
typedef enum {
    /** Error level: Critical errors that require immediate attention */
    AGLL_ERR,
    /** Warning level: Non-critical issues that may need attention */
    AGLL_WARN,
    /** Info level: General informational messages */
    AGLL_INFO,
    /** Debug level: Debugging information for developers */
    AGLL_DEBUG,
    /** Trace level: Detailed tracing information for in-depth debugging */
    AGLL_TRACE,
} ag_log_level;

/**
 *  A typedef for an array of `uint8_t` elements.
 *
 *  Uses the ARRAY_OF macro to create a typed array structure for `uint8_t` elements.
 *  It contains a pointer to the `uint8_t` data array and a `uint32_t` size variable.
 *
 *  Usage example:
 *  @code{.c}
 *  ag_buffer buffer;
 *  buffer.data = malloc(10 * sizeof(uint8_t));
 *  buffer.size = 10;
 *  @endcode
 *  @ingroup defines
 */
typedef ARRAY_OF(uint8_t) ag_buffer;

/**
 * @ingroup defines
 * A type alias for an array of C strings.
 */
typedef ARRAY_OF(const char *) ag_string_array;

/**
 * @struct ag_upstream_options
 * Represents options for configuring an upstream DNS server.
 *
 * Defines the various configuration options that can be used to specify an upstream DNS server.
 * By adjusting the values of these fields, users can fine-tune the behavior of the DNS proxy
 * server when sending DNS queries to upstream servers.
 */
typedef struct {
    /**
     * Server address.
     * One of the following kinds:
     * * `8.8.8.8:53` -- plain DNS (must specify IP address, not hostname)
     * * `tcp://8.8.8.8:53` -- plain DNS over TCP (must specify IP address, not hostname)
     * * `tls://dns.adguard.com` -- DNS-over-TLS
     * * `https://dns.adguard.com/dns-query` -- DNS-over-HTTPS
     * * `sdns://...` -- DNS stamp (see https://dnscrypt.info/stamps-specifications)
     * * `quic://dns.adguard.com:853` -- DNS-over-QUIC
     * * `h3://` -- DNS-over-HTTP/3
     */
    const char *address;

    /**
     * List of plain DNS servers.
     * List used to resolve the hostname in the upstream's address when necessary.
     * These servers will help establish the initial connection to the upstream DNS server
     * if its address is specified as a hostname.
     */
    ag_string_array bootstrap;

    /**
     * Upstream's IP address.
     * Pre-resolved IP address for the upstream server. If this field is specified, the @ref bootstrap
     * DNS servers won't be used for resolving the upstream's address.
     */
    ag_buffer resolved_ip_address;

    /** User-provided ID for this upstream */
    int32_t id;

    /** Index of the network interface to route traffic through, 0 is default */
    uint32_t outbound_interface_index;

    /**
     * (Optional) List of upstreams base64 encoded SPKI fingerprints to verify. If at least one of them is matched in the
     * certificate chain, the verification will be successful
     */
    ARRAY_OF(const char *) fingerprints;
} ag_upstream_options;

/**
 * @struct ag_dns64_settings
 * Represents settings for DNS64 prefix discovery.
 *
 * Defines the various configuration options that can be used to specify DNS64 prefix discovery settings.
 */
typedef struct {
    /** The upstreams to use for discovery of DNS64 prefixes (usually the system DNS servers) */
    NAMED_ARRAY_OF(ag_upstream_options, dns64_upstreams_s) upstreams;

    /** How many times, at most, to try DNS64 prefixes discovery before giving up */
    uint32_t max_tries;

    /** How long to wait before a dns64 prefixes discovery attempt */
    uint32_t wait_time_ms;
} ag_dns64_settings;

/**
 * @ingroup enums
 * Listener protocols for the networking system.
 */
typedef enum {
    /** UDP protocol */
    AGLP_UDP,
    /** TCP protocol */
    AGLP_TCP
} ag_listener_protocol;

/**
 * @ingroup enums
 * Blocking mode
 * Specifies how to respond to blocked requests.
 *
 * A request is blocked if it matches a blocking AdBlock-style rule,
 * or a blocking hosts-style rule. A blocking hosts-style rule is
 * a hosts-style rule with a loopback or all-zeroes address.
 *
 * Requests matching a hosts-style rule with an address that is
 * neither loopback nor all-zeroes are always responded
 * with the address specified by the rule.
 */
typedef enum {
    /** Respond with REFUSED response code */
    AGBM_REFUSED,
    /** Respond with NXDOMAIN response code */
    AGBM_NXDOMAIN,
    /**
     * Respond with an address that is all-zeroes, or
     * a custom blocking address, if it is specified, or
     * an empty SOA response if request type is not A/AAAA.
     */
    AGBM_ADDRESS,
    /**
     * Respond with an address that is all zeroes regardless of the custom blocking address setting,
     * or an empty SOA response if request type is not A/AAAA.
     */
    AGBM_UNSPECIFIED_ADDRESS,
} ag_dnsproxy_blocking_mode;

/**
 * @ingroup enums
 * DNS blocking reason
 */
typedef enum {
    /** Not blocked */
    AGDBR_NONE,
    /** Mozilla DoH detection */
    AGDBR_MOZILLA_DOH_DETECTION,
    /** DDR blocking */
    AGDBR_DDR,
    /** IPv6 blocking */
    AGDBR_IPV6,
    /** Query matched by rule */
    AGDBR_QUERY_MATCHED_BY_RULE,
    /** CNAME matched by rule */
    AGDBR_CNAME_MATCHED_BY_RULE,
    /** IP matched by rule */
    AGDBR_IP_MATCHED_BY_RULE,
    /** HTTPS matched by rule */
    AGDBR_HTTPS_MATCHED_BY_RULE,
} ag_dns_blocking_reason;

/**
 * @struct ag_proxy_settings_overrides
 * The subset of ag_dnsproxy_settings available for overriding on a specific listener.
 */
typedef struct {
    /** Overrides ag_dnsproxy_settings.block_ech if not null */
    bool *block_ech;
} ag_proxy_settings_overrides;

/**
 * @struct ag_listener_settings
 * Defines the various configuration options that can be used to specify DNS listener.
 */
typedef struct {
    /** The address to listen on */
    const char *address;
    /**
     * The port to listen on.
     * This is the port on which the listener will wait for incoming DNS queries.
     */
    uint16_t port;
    /** The protocol to listen for */
    ag_listener_protocol protocol;
    /**
     * Whether the listener should keep the TCP connection open after sending the first response.
     * If set to true, the connection will not be closed immediately,
     * allowing for multiple requests and responses over the same connection.
     */
    bool persistent;
    /**
     * Idle timeout.
     * Duration (in milliseconds) after which the listener should close the TCP connection if no
     * requests have been received. This setting helps to prevent idle connections from consuming resources.
     */
    uint32_t idle_timeout_ms;
    /** Overridden settings */
    ag_proxy_settings_overrides settings_overrides;
} ag_listener_settings;

/**
 * @ingroup enums
 * Proxy protocol.
 */
typedef enum {
    /** Plain HTTP proxy */
    AGOPP_HTTP_CONNECT,
    /** HTTPs proxy */
    AGOPP_HTTPS_CONNECT,
    /** SOCKS4 proxy */
    AGOPP_SOCKS4,
    /** SOCKS5 proxy without UDP support */
    AGOPP_SOCKS5,
    /** SOCKS5 proxy with UDP support */
    AGOPP_SOCKS5_UDP,
} ag_outbound_proxy_protocol;

/**
 * @struct ag_outbound_proxy_auth_info
 * Defines the fields for the authentication information used with an outbound proxy.
 */
typedef struct {
    const char *username;
    const char *password;
} ag_outbound_proxy_auth_info;

/**
 * @struct ag_outbound_proxy_settings
 * Defines the various configuration options that can be used to specify an outbound proxy.
 */
typedef struct {
    /** The proxy protocol */
    ag_outbound_proxy_protocol protocol;

    /** The proxy server IP address or hostname */
    const char *address;

    /** The proxy server port */
    uint16_t port;

    /**
     * List of the DNS server URLs to be used to resolve a hostname in the proxy server address.
     * The URLs MUST contain the resolved server addresses, not hostnames.
     * E.g. `https://94.140.14.14` is correct, while `dns.adguard.com:53` is not.
     * MUST NOT be empty in case the `address` is a hostname.
     */
    ag_string_array bootstrap;

    /** The authentication information */
    ag_outbound_proxy_auth_info *auth_info;

    /** If true and the proxy connection is secure, the certificate won't be verified */
    bool trust_any_certificate;
} ag_outbound_proxy_settings;

/**
 * @struct ag_filter_params
 * Represents the parameters for an individual filter used in the filter engine.
 */
typedef struct {
    /** Filter ID */
    int32_t id;
    /** Path to the filter list file or string with rules, depending on value of in_memory */
    const char *data;
    /** If true, data is rules, otherwise data is path to file with rules */
    bool in_memory;
} ag_filter_params;

/**
 * @struct ag_filter_engine_params
 * Represents the filter engine parameters.
 *
 * The filters field contains an array of ag_filter_params structures,
 * which define the parameters for individual filters used in the filter engine.
 */
typedef struct {
    NAMED_ARRAY_OF(ag_filter_params, filters_s) filters;
} ag_filter_engine_params;


/**
 * @struct ag_dnsproxy_settings
 * Represents settings for the AdGuard DNS proxy.
 *
 * Defines the various configuration options that can be used to specify the AdGuard DNS proxy settings.
 */
typedef struct {
    /**
     * List of upstreams representing the list of primary upstream DNS servers.
     * The DNS proxy server will send queries to these servers.
     */
    NAMED_ARRAY_OF(ag_upstream_options, upstreams_s) upstreams; /** List of upstreams */
    /**
     * List of fallback upstreams, representing the list of fallback upstream DNS servers.
     * DNS proxy server will send queries to these servers if none of the primary upstreams respond.
     */
    NAMED_ARRAY_OF(ag_upstream_options, fallbacks_s) fallbacks; /** List of fallbacks */
    /**
     * Requests for these domains will be forwarded directly to the fallback upstreams, if there are any.
     * A wildcard character, `*`, which stands for any number of characters, is allowed to appear multiple
     * times anywhere except at the end of the domain (which implies that a domain consisting only of
     * wildcard characters is invalid).
     */
    ag_string_array fallback_domains;
    /** (Optional) DNS64 prefix discovery settings */
    ag_dns64_settings *dns64;
    /** TTL of a blocking response */
    uint32_t blocked_response_ttl_secs;
    /** Filtering engine parameters */
    ag_filter_engine_params filter_params;
    /** List of listener parameters */
    NAMED_ARRAY_OF(ag_listener_settings, listeners_s) listeners;
    /** Outbound proxy settings */
    ag_outbound_proxy_settings *outbound_proxy;
    /** If true, all AAAA requests will be blocked */
    bool block_ipv6;
    /** If true, the bootstrappers are allowed to fetch AAAA records */
    bool ipv6_available;
    /** How to respond to requests blocked by AdBlock-style rules */
    ag_dnsproxy_blocking_mode adblock_rules_blocking_mode;
    /** How to respond to requests blocked by hosts-style rules */
    ag_dnsproxy_blocking_mode hosts_rules_blocking_mode;
    /** Custom IPv4 address to return for filtered requests */
    const char *custom_blocking_ipv4;
    /** Custom IPv6 address to return for filtered requests */
    const char *custom_blocking_ipv6;
    /** Maximum number of cached responses (may be 0) */
    uint32_t dns_cache_size;
    /** Maximum amount of time, in milliseconds, allowed for upstream exchange (0 means default) */
    uint32_t upstream_timeout_ms;
    /** Enable optimistic DNS caching */
    bool optimistic_cache;
    /**
     * Enable DNSSEC OK extension.
     * This options tells server that we want to receive DNSSEC records along with normal queries.
     * If they exist, request processed event will have DNSSEC flag on.
     * @warning may increase data usage and probability of TCP fallbacks.
     */
    bool enable_dnssec_ok;
    /** If enabled, detect retransmitted requests and handle them using fallback upstreams only */
    bool enable_retransmission_handling;
    /** If enabled, strip Encrypted Client Hello parameters from responses */
    bool block_ech;
    /** If enabled, remove h3 from ALPN parameter in HTTPS records */
    bool block_h3_alpn;
    /** If true, all upstreams are queried in parallel, and the first response is returned */
    bool enable_parallel_upstream_queries;
    /**
     * If true, normal queries will be forwarded to fallback upstreams if all normal upstreams failed.
     * Otherwise, fallback upstreams will only be used to resolve domains from `fallback_domains`.
     */
    bool enable_fallback_on_upstreams_failure;
    /**
     * If true, when all upstreams (including fallback upstreams) fail to provide a response.
     * The proxy will respond with a SERVFAIL packet. Otherwise, no response is sent on such a failure.
     */
    bool enable_servfail_on_upstreams_failure;
    /** Enable HTTP/3 for DNS-over-HTTPS upstreams if it's able to connect quicker */
    bool enable_http3;
    /** Enable post-quantum cryptography */
    bool enable_post_quantum_cryptography;
} ag_dnsproxy_settings;

/**
 * @struct ag_dns_request_processed_event
 * Represents a DNS request processed event.
 *
 * Defines the various fields of a DNS request processed event.
 */
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
    ag_string_array rules;
    /** Corresponding filter ID for each matched rule */
    NAMED_ARRAY_OF(const int32_t, filters_list_ids_s) filter_list_ids;
    /** True if the matched rule is a whitelist rule */
    bool whitelist;
    /** If not NULL, contains the error description */
    const char *error;
    /** True if this response was served from the cache */
    bool cache_hit;
    /** True if this response has DNSSEC rrsig */
    bool dnssec;
    /** DNS blocking reason */
    ag_dns_blocking_reason blocking_reason;
} ag_dns_request_processed_event;

/**
 * @struct ag_certificate_verification_event
 * Represents an event generated during certificate verification.
 */
typedef struct {
    /** Leaf certificate */
    ag_buffer certificate;
    /** Certificate chain */
    NAMED_ARRAY_OF(ag_buffer, chain_s) chain;
} ag_certificate_verification_event;

/**
 * @ingroup defines
 * Callback function for processing DNS requests.
 *
 * Called synchronously right after a request has been processed, but before a response is returned.
 * @param event Pointer to the ag_dns_request_processed_event structure
 *              containing information about the processed DNS request
 */
typedef void (*ag_dns_request_processed_cb)(const ag_dns_request_processed_event *);

/**
 * @ingroup enums
 * Certificate verification results.
 *
 * Defines the possible results of certificate verification.
 */
typedef enum {
    /** OK: Certificate verification was successful */
    AGCVR_OK,
    /** Error: Failed to create a certificate object */
    AGCVR_ERROR_CREATE_CERT,
    /** Error: Failed to access the certificate store */
    AGCVR_ERROR_ACCESS_TO_STORE,
    /** Error: Certificate verification failed */
    AGCVR_ERROR_CERT_VERIFICATION,
    /** Count: The total number of enumeration values */
    AGCVR_COUNT
} ag_certificate_verification_result;

/**
 * @ingroup defines
 * Callback function for certificate verification.
 *
 * This function is called on an unspecified thread when a certificate needs to be verified.
 *
 * @param event Pointer to the ag_certificate_verification_event structure
 *              containing information about the certificate to be verified
 * @return ag_certificate_verification_result The result of the certificate verification
 */
typedef ag_certificate_verification_result (*ag_certificate_verification_cb)(const ag_certificate_verification_event *);

/**
 * @ingroup defines
 * Callback function for logging messages.
 *
 * Called when we need to log a message. The message is already formatted, including the line terminator.
 * @param attachment User-defined attachment provided when setting the callback
 * @param level The log level of the message
 * @param message The formatted log message, including the line terminator
 * @param length The length of the log message, in bytes
 */
typedef void (*ag_log_cb)(void *attachment, ag_log_level level, const char *message, uint32_t length);


/**
 * @struct ag_dnsproxy_events
 * Represents the events that can be subscribed to in the DNS proxy.
 *
 * Defines the various callback functions that can be subscribed to in the DNS proxy.
 */
typedef struct {
    ag_dns_request_processed_cb on_request_processed;
    ag_certificate_verification_cb on_certificate_verification;
} ag_dnsproxy_events;

/**
 * @ingroup enums
 * Supported protocol types for server stamps.
 * Defines the supported protocol types for server stamps.
 */
typedef enum {
    /** Standard DNS protocol */
    AGSPT_PLAIN,
    /** Encrypted DNS protocol using DNSCrypt */
    AGSPT_DNSCRYPT,
    /** DNS over HTTPS protocol */
    AGSPT_DOH,
    /** DNS over TLS protocol */
    AGSPT_TLS,
    /** DNS over QUIC protocol */
    AGSPT_DOQ,
} ag_stamp_proto_type;

/**
 * @ingroup enums
 * Server information properties.
 */
typedef enum {
    /** Resolver does DNSSEC validation */
    AGSIP_DNSSEC = 1 << 0,
    /** Resolver does not record logs */
    AGSIP_NO_LOG = 1 << 1,
    /** Resolver doesn't intentionally block domains */
    AGSIP_NO_FILTER = 1 << 2,
} ag_server_informal_properties;

/**
 * @struct ag_dns_stamp
 * Represents a DNS stamp.
 *
 * Defines the various fields of a DNS stamp.
 */
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
    NAMED_ARRAY_OF(ag_buffer, hashes_s) hashes;
    /** Server properties */
    ag_server_informal_properties *properties;
} ag_dns_stamp;

/**
 * @ingroup defines
 * An opaque data type representing a DNS rule template.
 */
typedef void ag_dns_rule_template;

/**
 * @ingroup enums
 * Rule generation options.
 */
typedef enum {
    /** Add $important modifier */
    AGRGO_IMPORTANT = 1 << 0,
    /** Add $dnstype modifier */
    AGRGO_DNSTYPE = 1 << 1,
} ag_rule_generation_options;

/**
 * @struct ag_dns_filtering_log_action
 * Represents an action that can be taken as a result of applying a DNS filter rule.
 *
 * Defines the various fields of an action that can be taken as a result of applying a DNS filter rule.
 */
typedef struct {
    /** A set of rule templates */
    NAMED_ARRAY_OF(const ag_dns_rule_template *, templates_s) templates;
    /** Options that are allowed to be passed to `generate_rule` */
    uint32_t allowed_options;
    /** Options that are required for the generated rule to be correct */
    uint32_t required_options;
    /** Whether something will be blocked or un-blocked as a result of this action */
    bool blocking;
} ag_dns_filtering_log_action;

/**
 * @ingroup enums
 * Dnsproxy init result.
 *
 * Defines the possible results of DNS proxy initialization.
 */
typedef enum {
    /** The DNS proxy is not set */
    AGDPIR_PROXY_NOT_SET,
    /** The event loop is not set */
    AGDPIR_EVENT_LOOP_NOT_SET,
    /** The provided address is invalid */
    AGDPIR_INVALID_ADDRESS,
    /** The proxy is empty */
    AGDPIR_EMPTY_PROXY,
    /** There is an error in the protocol */
    AGDPIR_PROTOCOL_ERROR,
    /**  Failed to initialize the listener */
    AGDPIR_LISTENER_INIT_ERROR,
    /** The provided IPv4 address is invalid */
    AGDPIR_INVALID_IPV4,
    /** The provided IPv6 address is invalid */
    AGDPIR_INVALID_IPV6,
    /** Failed to initialize the upstream */
    AGDPIR_UPSTREAM_INIT_ERROR,
    /** Failed to initialize the fallback filter */
    AGDPIR_FALLBACK_FILTER_INIT_ERROR,
    /** Failed to load the filter */
    AGDPIR_FILTER_LOAD_ERROR,
    /** The memory limit has been reached */
    AGDPIR_MEM_LIMIT_REACHED,
    /** The filter ID is not unique */
    AGDPIR_NON_UNIQUE_FILTER_ID,
    /** DNS proxy initialization was successful */
    AGDPIR_OK,
} ag_dnsproxy_init_result;

/**
 * @struct ag_dns_message_info
 * Holds out-of-band information about a DNS message or how to process it.
 */
typedef struct {
    /**
     * If `true`, the proxy will handle the message transparently: queries are returned to the caller
     * instead of being forwarded to the upstream by the proxy, responses are processed as if they were received
     * from an upstream, and the processed response is returned to the caller. The proxy may return a response
     * when transparently handling a query if the query is blocked. The proxy may still perform an upstream
     * query when handling a message transparently, for example, to process CNAME-rewrites.
     */
    bool transparent;
} ag_dns_message_info;

/**
 * @ingroup defines
 * Callback function for asynchronous message processing.
 * This function is called on an unspecified thread when a result of `handle_message_async` is ready.
 */
typedef void (*ag_handle_message_async_cb)(const ag_buffer *result);

/**
 * @ingroup defines
 * An opaque data type representing a DNS Proxy.
 */
typedef void ag_dnsproxy;

/**
 * @defgroup api API functions
 * This collection of functions enables interaction with a proxy server and related objects,
 * including logging capabilities and more.
 *
 * Usage example:
 * @code{.c}
 * int main() {
 *     ag_dnsproxy_settings *settings = ag_dnsproxy_settings_get_default();
 *     ag_upstream_options upstream = {
 *         .address = "tls://1.1.1.1",
 *         .id = 42,
 *     };
 *     settings->upstreams.data = &upstream;
 *     settings->upstreams.size = 1;
 *
 *     ag_dnsproxy_init_result result;
 *     ag_dnsproxy_events events = {0};
 *     const char *message = NULL;
 *     ag_dnsproxy *proxy = ag_dnsproxy_init(settings, &events, &result, &message);
 *
 *     ...
 *     ag_dnsproxy_deinit(proxy);
 * }
 * @endcode
 */

/**
 * @ingroup api
 * Initialize and starts a DNS proxy server based on the provided settings and events.
 * @param out_result upon return, contains the result of the operation
 * @param out_message upon return, contains the error or warning message, or is unchanged
 * @return The proxy handle, or NULL in case of an error
 */
AG_EXPORT ag_dnsproxy *ag_dnsproxy_init(const ag_dnsproxy_settings *settings, const ag_dnsproxy_events *events,
                                        ag_dnsproxy_init_result *out_result, const char **out_message);

/**
 * @ingroup api
 * Stop and destroy a proxy.
 * @param proxy a proxy handle
 */
AG_EXPORT void ag_dnsproxy_deinit(ag_dnsproxy *proxy);

/**
 * @ingroup api
 * Reapply DNS proxy settings with optional filter reloading.
 * @param proxy a proxy handle
 * @param settings new DNS proxy configuration to apply
 * @param reapply_filters if true, DNS filters will be reloaded from settings.
 *                        If false, existing filters are preserved (fast update).
 * @param out_result upon return, contains the result of the operation
 * @param out_message upon return, contains the error or warning message, or is unchanged
 * @return true if reapplying succeeded, false otherwise
 */
AG_EXPORT bool ag_dnsproxy_reapply_settings(ag_dnsproxy *proxy, const ag_dnsproxy_settings *settings,
                                            bool reapply_filters, ag_dnsproxy_init_result *out_result,
                                            const char **out_message);

/**
 * @ingroup api
 * Process a DNS message and return the response.
 * @param message a DNS message in wire format
 * @param info additional parameters
 * @return The DNS response in wire format
 * @note The caller is responsible for freeing both buffers with `ag_buffer_free()`
 */
AG_EXPORT ag_buffer ag_dnsproxy_handle_message(ag_dnsproxy *proxy, ag_buffer message, const ag_dns_message_info *info);

/**
 * @ingroup api
 * Process a DNS message and call `handler` on an unspecified thread with the response.
 * @param message a DNS message in wire format
 * @param info additional parameters
 * @note The caller is responsible for freeing `message` with `ag_buffer_free()`
 */
AG_EXPORT void ag_dnsproxy_handle_message_async(ag_dnsproxy *proxy, ag_buffer message, const ag_dns_message_info *info,
        ag_handle_message_async_cb handler);

/**
 * @ingroup api1
 * Get current proxy settings.
 * @return The current proxy settings
 * @note The caller is responsible for freeing the returned pointer with `ag_dnsproxy_settings_free()`
 */
AG_EXPORT ag_dnsproxy_settings *ag_dnsproxy_get_settings(ag_dnsproxy *proxy);

/**
 * @ingroup api
 * Get default proxy settings. The caller is responsible for freeing
 * the returned pointer with `ag_dnsproxy_settings_free()`.
 * @return The default proxy settings
 */
AG_EXPORT ag_dnsproxy_settings *ag_dnsproxy_settings_get_default();

/**
 * @ingroup api
 * This function frees the memory occupied by the given DNS proxy settings pointer.
 * @param settings Pointer to a DNS proxy settings structure
 */
AG_EXPORT void ag_dnsproxy_settings_free(ag_dnsproxy_settings *settings);

/**
 * @ingroup api
 * Free a buffer.
 * @param buf buffer
 */
AG_EXPORT void ag_buffer_free(ag_buffer buf);

/**
 * @ingroup api
 * Set the log verbosity level.
 */
AG_EXPORT void ag_set_log_level(ag_log_level level);

/**
 * @ingroup api
 * Set the logging function.
 * @param attachment an argument to the logging function
 */
AG_EXPORT void ag_set_log_callback(ag_log_cb callback, void *attachment);

/**
 * @ingroup api
 * Parse a DNS stamp string. The caller is responsible for freeing
 * the result with `ag_parse_dns_stamp_result_free()`.
 * @param stamp_str "sdns://..." string
 * @param error on output, if an error occurred, contains the error description (free with `ag_str_free()`)
 * @return The parsed stamp, or NULL if an error occurred
 */
AG_EXPORT ag_dns_stamp *ag_dns_stamp_from_str(const char *stamp_str, const char **error);

/**
 * @ingroup api
 * Free a ag_parse_dns_stamp_result pointer.
 * @param stamp DNS stamp
 */
AG_EXPORT void ag_dns_stamp_free(ag_dns_stamp *stamp);

/**
 * @ingroup api
 * Convert a DNS stamp to "sdns://..." string.
 * @param stamp DNS stamp
 * @return DNS Stamp as string
 * @note Free the string with `ag_str_free()`
 */
AG_EXPORT const char *ag_dns_stamp_to_str(ag_dns_stamp *stamp);

/**
 * @ingroup api
 * Convert a DNS stamp to string that can be used as an upstream URL.
 * @param stamp DNS stamp
 * @return DNS Stamp as string
 * @note Free the string with `ag_str_free()`
 */
AG_EXPORT const char *ag_dns_stamp_pretty_url(ag_dns_stamp *stamp);

/**
 * @ingroup api
 * Convert a DNS stamp to string that can NOT be used as an upstream URL, but may be prettier.
 * @param stamp DNS stamp
 * @return DNS Stamp as string
 * @note Free the string with `ag_str_free()`
 */
AG_EXPORT const char *ag_dns_stamp_prettier_url(ag_dns_stamp *stamp);

/**
 * @ingroup api
 * Check if an upstream is valid and working.
 * The caller is responsible for freeing the result with `ag_str_free()`.
 * @param ipv6_available If true, bootstrapper is allowed to make AAAA queries (if IPv6 is available)
 * @param timeout_ms Maximum amount of time allowed for upstream exchange (in milliseconds)
 * @param offline If true, don't perform online upstream check
 * @return NULL if everything is ok, or
 *         an error message.
 */
AG_EXPORT const char *ag_test_upstream(const ag_upstream_options *upstream, uint32_t timeout_ms, bool ipv6_available,
        ag_certificate_verification_cb on_certificate_verification, bool offline);

/**
 * @ingroup api
 * Check if string is a valid rule.
 * @return TRUE if rule is valid, false otherwise
 */
AG_EXPORT bool ag_is_valid_dns_rule(const char *str);

/**
 * @ingroup api
 * Get C APi version.
 * @return the C API version (hash of this file)
 */
AG_EXPORT const char *ag_get_capi_version();

/**
 * @ingroup api
 * Return the DNS proxy library version.
 * @note Do NOT free the returned string
 */
AG_EXPORT const char *ag_dnsproxy_version();

/**
 * @ingroup api
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

/**
 * @ingroup api
 * Suggest rules based on filtering log event.
 * @return The action freed with `ag_dns_filtering_log_action_free()` on success. NULL on error
 */
AG_EXPORT ag_dns_filtering_log_action *ag_dns_filtering_log_action_from_event(
        const ag_dns_request_processed_event *event);

/**
 * @ingroup api
 * Free an action.
 */
AG_EXPORT void ag_dns_filtering_log_action_free(ag_dns_filtering_log_action *action);

/**
 * @ingroup api
 * Generate a rule from a template (obtained from `ag_dns_filtering_log_action`) and a corresponding event.
 * @return The rule freed with `ag_str_free()` on success, NULL on error
 */
AG_EXPORT char *ag_dns_generate_rule_with_options(
        const ag_dns_rule_template *tmplt, const ag_dns_request_processed_event *event, uint32_t options);

#ifdef __cplusplus
} // extern "C"
#endif
