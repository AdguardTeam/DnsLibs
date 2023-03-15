#import <Foundation/Foundation.h>

#import "AGDnsProxyEvents.h"

/**
 * DNS proxy error domain
 */
extern NSErrorDomain const AGDnsProxyErrorDomain;

/**
 * DNS error codes
 */
typedef NS_ENUM(NSInteger, AGDnsProxyInitError) {
    AGDPE_PROXY_NOT_SET,
    AGDPE_EVENT_LOOP_NOT_SET,
    AGDPE_INVALID_ADDRESS,
    AGDPE_EMPTY_PROXY,
    AGDPE_PROTOCOL_ERROR,
    AGDPE_LISTENER_INIT_ERROR,
    AGDPE_INVALID_IPV4,
    AGDPE_INVALID_IPV6,
    AGDPE_UPSTREAM_INIT_ERROR,
    AGDPE_FALLBACK_FILTER_INIT_ERROR,
    AGDPE_FILTER_LOAD_ERROR,
    AGDPE_MEM_LIMIT_REACHED,
    AGDPE_NON_UNIQUE_FILTER_ID,

    AGDPE_TEST_UPSTREAM_ERROR,
    AGDPE_PROXY_INIT_ERROR,
    AGDPE_PROXY_INIT_LISTENER_ERROR,
    AGDPE_PROXY_INIT_HELPER_ERROR,
    AGDPE_PROXY_INIT_HELPER_BIND_ERROR,
};

/**
 * Logging levels
 */
typedef NS_ENUM(NSInteger, AGLogLevel) {
    AGLL_ERR,
    AGLL_WARN,
    AGLL_INFO,
    AGLL_DEBUG,
    AGLL_TRACE,
};

/**
 * Listener protocols
 */
typedef NS_ENUM(NSInteger, AGListenerProtocol) {
    AGLP_UDP,
    AGLP_TCP,
};

/**
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
typedef NS_ENUM(NSInteger, AGBlockingMode) {
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
};

@interface AGLogger : NSObject

/**
 * Set the default logging level
 *
 * @param level logging level to be set
 */
+ (void) setLevel: (AGLogLevel) level;

/**
 * A function that outputs a log message.
 * The message is already formatted, including the line terminator.
 */
typedef void (^logCallback)(AGLogLevel level, const char *msg, int length);

/**
 * Set log callback
 *
 * @param func logging function
 */
+ (void) setCallback: (logCallback) func;

@end


@interface AGDnsUpstream : AGDnsXPCObject <NSSecureCoding>
/**
 * A DNS server address:
 *      8.8.8.8:53 -- plain DNS
 *      tcp://8.8.8.8:53 -- plain DNS over TCP
 *      tls://1.1.1.1 -- DNS-over-TLS
 *      https://dns.adguard.com/dns-query -- DNS-over-HTTPS
 *      sdns://... -- DNS stamp (see https://dnscrypt.info/stamps-specifications)
 *      quic://dns.adguard.com:853 -- DNS-over-QUIC
 */
@property(nonatomic) NSString *address;
/**
 * List of plain DNS servers to be used to resolve DOH/DOT hostnames (if any)
 */
@property(nonatomic) NSArray<NSString *> *bootstrap;
/**
 * Default upstream timeout in milliseconds. Also used as a timeout for bootstrap DNS requests.
 * timeout = 0 means infinite timeout.
 */
@property(nonatomic) NSInteger timeoutMs;
/**
 * Resolver's IP address. In the case if it's specified,
 * bootstrap DNS servers won't be used at all.
 */
@property(nonatomic) NSData *serverIp;
/**
 * User-provided ID for this upstream
 */
@property(nonatomic) NSInteger id;
/**
 * Name of the network interface to route traffic through, nil is default
 */
@property(nonatomic) NSString *outboundInterfaceName;

/**
 * (Optional) List of upstreams base64 encoded SPKI fingerprints to verify. If at least one of them is matched in the
 * certificate chain, the verification will be successful
 */
@property(nonatomic) NSArray<NSString *> *fingerprints;

- (instancetype)initWithCoder:(NSCoder *)coder;

- (void)encodeWithCoder:(NSCoder *)coder;

- (NSString*)description;

@end

@interface AGDns64Settings : AGDnsXPCObject <NSSecureCoding>

/**
 * The upstream to use for discovery of DNS64 prefixes
 */
@property(nonatomic) NSArray<AGDnsUpstream *> *upstreams;

/**
 * How many times, at most, to try DNS64 prefixes discovery before giving up
 */
@property(nonatomic) NSInteger maxTries;

/**
 * How long to wait before a dns64 prefixes discovery attempt, in milliseconds
 */
@property(nonatomic) NSInteger waitTimeMs;

- (instancetype)initWithCoder:(NSCoder *)coder;

- (void)encodeWithCoder:(NSCoder *)coder;

- (NSString*)description;

@end

@interface AGListenerSettings : AGDnsXPCObject <NSSecureCoding>

/**
 * The address to listen on
 */
@property(nonatomic) NSString *address;

/**
 * The port to listen on
 */
@property(nonatomic) NSInteger port;

/**
 * The protocol to listen for
 */
@property(nonatomic) AGListenerProtocol proto;

/**
 * Don't close the TCP connection after sending the first response
 */
@property(nonatomic) BOOL persistent;

/**
 * Close the TCP connection this long after the last request received, in milliseconds
 */
@property(nonatomic) NSInteger idleTimeoutMs;

- (instancetype)initWithCoder:(NSCoder *)coder;

- (void)encodeWithCoder:(NSCoder *)coder;

- (NSString*)description;

@end

/**
 * Outbound proxy protocols
 */
typedef NS_ENUM(NSInteger, AGOutboundProxyProtocol) {
    AGOPP_HTTP_CONNECT, // Plain HTTP proxy
    AGOPP_HTTPS_CONNECT, // HTTPs proxy
    AGOPP_SOCKS4, // Socks4 proxy
    AGOPP_SOCKS5, // Socks5 proxy without UDP support
    AGOPP_SOCKS5_UDP, // Socks5 proxy with UDP support
};

@interface AGOutboundProxyAuthInfo : AGDnsXPCObject <NSSecureCoding>
/** User name for authentication */
@property(nonatomic) NSString *username;
/** Password for authentication */
@property(nonatomic) NSString *password;

- (instancetype) init NS_UNAVAILABLE;

- (instancetype)initWithCoder:(NSCoder *)coder;

- (void)encodeWithCoder:(NSCoder *)coder;

- (NSString*)description;

@end

@interface AGOutboundProxySettings : AGDnsXPCObject <NSSecureCoding>
/** The proxy protocol */
@property(nonatomic) AGOutboundProxyProtocol protocol;
/** The proxy server IP address or hostname */
@property(nonatomic) NSString *address;
/** The proxy server port */
@property(nonatomic) NSInteger port;
/**
 * List of the DNS server URLs to be used to resolve a hostname in the proxy server address.
 * The URLs MUST contain the resolved server addresses, not hostnames.
 * E.g. `https://94.140.14.14` is correct, while `dns.adguard.com:53` is not.
 * MUST NOT be empty in case the `address` is a hostname.
 */
@property(nonatomic) NSArray<NSString *> *bootstrap;
/** The authentication information (if nil, authentication is not performed) */
@property(nonatomic) AGOutboundProxyAuthInfo *authInfo;
/** If true and the proxy connection is secure, the certificate won't be verified */
@property(nonatomic) BOOL trustAnyCertificate;

- (instancetype) init NS_UNAVAILABLE;

- (instancetype)initWithCoder:(NSCoder *)coder;

- (void)encodeWithCoder:(NSCoder *)coder;

- (NSString*)description;

@end

@interface AGDnsFilterParams : AGDnsXPCObject <NSSecureCoding>
/**
 * Filter identifier
 */
@property(nonatomic) NSInteger id;
/**
 * Filter data
 * Either path to file with rules, or rules as a string
 */
@property(nonatomic) NSString *data;
/**
 * If YES, data is rules, otherwise data is path to file with rules
 */
@property(nonatomic) BOOL inMemory;

- (instancetype)initWithCoder:(NSCoder *)coder;

- (void)encodeWithCoder:(NSCoder *)coder;

- (NSString*)description;

@end

@interface AGDnsProxyConfig : AGDnsXPCObject <NSSecureCoding>
/**
 * Upstreams settings
 */
@property(nonatomic) NSArray<AGDnsUpstream *> *upstreams;
/**
 * Fallback upstreams settings
 */
@property(nonatomic) NSArray<AGDnsUpstream *> *fallbacks;
/**
 * Requests for these domains will be forwarded directly to the fallback upstreams, if there are any.
 * A wildcard character, `*`, which stands for any number of characters, is allowed to appear multiple
 * times anywhere except at the end of the domain (which implies that a domain consisting only of
 * wildcard characters is invalid).
 */
@property(nonatomic) NSArray<NSString *> *fallbackDomains;
/**
 * If enabled, DNS search domains will be automatically appended to the fallback domains,
 * allowing to forward requests for, e.g., *.local, directly to the fallback upstreams.
 */
@property(nonatomic) BOOL detectSearchDomains;
/**
 * Filters
 */
@property(nonatomic) NSArray<AGDnsFilterParams *> *filters;
#if TARGET_OS_IPHONE
/**
 * If not zero, the filtering engine might not load some rules from the configured
 * filters to try to keep the estimated memory usage below this limit.
 * If any rules are not loaded because of this limit, a warning will be returned
 * from `[AGDnsProxy initWithConfig:]`.
 */
@property(nonatomic) NSUInteger filtersMemoryLimitBytes;
#endif // TARGET_OS_IPHONE
/**
 * TTL of the record for the blocked domains (in seconds)
 */
@property(nonatomic) NSInteger blockedResponseTtlSecs;
/**
 * DNS64 settings. If nil, DNS64 is disabled
 */
@property(nonatomic) AGDns64Settings *dns64Settings;
/**
 * List of addresses/ports/protocols/etc... to listen on
 */
@property(nonatomic) NSArray<AGListenerSettings *> *listeners;
/**
 * Outbound proxy settings
 */
@property(nonatomic) AGOutboundProxySettings *outboundProxy;
/**
 * If false, bootstrappers will fetch only A records.
 */
@property(nonatomic) BOOL ipv6Available;
/**
 * Block AAAA requests.
 */
@property(nonatomic) BOOL blockIpv6;
/**
 * How to respond to requests blocked by AdBlock-style rules
 */
@property(nonatomic) AGBlockingMode adblockRulesBlockingMode;
/**
 * How to respond to requests blocked by hosts-style rules
 */
@property(nonatomic) AGBlockingMode hostsRulesBlockingMode;
/**
 * Custom IPv4 address to return for filtered requests
 */
@property(nonatomic) NSString *customBlockingIpv4;
/**
 * Custom IPv6 address to return for filtered requests
 */
@property(nonatomic) NSString *customBlockingIpv6;
/**
 * Maximum number of cached responses
 */
@property(nonatomic) NSUInteger dnsCacheSize;
/**
 * Enable optimistic DNS caching
 */
@property(nonatomic) BOOL optimisticCache;
/**
 * Enable DNSSEC OK extension.
 * This options tells server that we want to receive DNSSEC records along with normal queries.
 * If they exist, request processed event will have DNSSEC flag on.
 * WARNING: may increase data usage and probability of TCP fallbacks.
 */
@property(nonatomic) BOOL enableDNSSECOK;
/**
 * If enabled, detect retransmitted requests and handle them using fallback upstreams only.
 */
@property(nonatomic) BOOL enableRetransmissionHandling;
/**
 * If enabled, our own route resolver will be used to resolve routes.
 * This is needed when DnsProxy is used inside network extension and needs to use routes of some VPN.
 */
@property(nonatomic) BOOL enableRouteResolver;
/**
 * If enabled, strip Encrypted Client Hello parameters from responses.
 */
@property(nonatomic) BOOL blockEch;
/**
 * If true, all upstreams are queried in parallel, and the first response is returned.
 */
@property(nonatomic) BOOL enableParallelUpstreamQueries;
/**
 * If true, normal queries will be forwarded to fallback upstreams if all normal upstreams failed.
 * Otherwise, fallback upstreams will only be used to resolve domains from `fallback_domains`.
 */
@property(nonatomic) BOOL enableFallbackOnUpstreamsFailure;
/**
 * If true, when all upstreams (including fallback upstreams) fail to provide a response,
 * the proxy will respond with a SERVFAIL packet. Otherwise, no response is sent on such a failure.
 */
@property(nonatomic) BOOL enableServfailOnUpstreamsFailure;
/**
 * Enable HTTP/3 for DNS-over-HTTPS upstreams if it's able to connect quicker.
 */
@property(nonatomic) BOOL enableHttp3;
/**
 * Path to adguard-tun-helper (macOS only)
 */
@property(nonatomic) NSString *helperPath;

- (instancetype)initWithCoder:(NSCoder *)coder;

- (void)encodeWithCoder:(NSCoder *)coder;

- (NSString*)description;

/**
 * @brief Get default DNS proxy settings
 */
+ (instancetype) getDefault;
@end

typedef NS_ENUM(NSUInteger, AGRuleGenerationOptions) {
    AGRGOImportant = 1u << 0, /**< Add an $important modifier. */
    AGRGODnstype = 1u << 1, /**< Add a $dnstype modifier. */
};

@interface AGRuleTemplate : NSObject
- (NSString *)description; /**< String representation. */
/**
 * Generate a rule using this template and the specified options.
 * @param options Union of `AGRuleGenerationOptions` values.
 * @return The resulting rule or `nil` on error.
 */
- (NSString *)generateRuleWithOptions:(NSUInteger)options;
@end

@interface AGFilteringLogAction : NSObject
@property(nonatomic) NSArray<AGRuleTemplate *> *templates; /**< A set of rule templates. */
@property(nonatomic) NSUInteger allowedOptions; /**< Options that are allowed to be passed to `generate_rule`. */
@property(nonatomic) NSUInteger requiredOptions; /**< Options that are required for the generated rule to be correct. */
@property(nonatomic) BOOL blocking; /**< Whether something will be blocked or un-blocked as a result of this action. */
/**
 * Suggest an action based on filtering event.
 * @return Action or nil on error.
 */
+ (instancetype)actionFromEvent:(AGDnsRequestProcessedEvent *)event;
@end

@interface AGDnsProxy : NSObject
/**
 * @brief Initialize DNS proxy with the given configuration
 *
 * @param config proxy configuration
 * @param events proxy events handler
 * @param error  error reference
 */
- (instancetype) initWithConfig: (AGDnsProxyConfig *) config
                        handler: (AGDnsProxyEvents *) events
                          error: (NSError **) error NS_SWIFT_NOTHROW;

/**
 * @brief Process UDP/TCP packet payload
 *
 * @param Packet data to process
 * @param completionHandler Completion handler
 * @return Response packet payload, or
 *         nil if nothing shoud be sent in response
 */
- (void) handlePacket: (NSData *) packet completionHandler: (void (^)(NSData *)) completionHandler;

/**
 * Stop DnsProxy. Should be called before dealloc.
 */
- (void) stop;

/**
* Check if string is a valid rule
* @param str string to check
* @return true if string is a valid rule, false otherwise
*/
+ (BOOL) isValidRule: (NSString *) str;

/**
 * Return the DNS proxy library version.
 */
+ (NSString *) libraryVersion;

@end

typedef NS_ENUM(NSInteger, AGStampProtoType) {
    /** plain is plain DNS */
    AGSPT_PLAIN,
    /** dnscrypt is DNSCrypt */
    AGSPT_DNSCRYPT,
    /** doh is DNS-over-HTTPS */
    AGSPT_DOH,
    /** tls is DNS-over-TLS */
    AGSPT_TLS,
    /** doq is DNS-over-QUIC */
    AGSPT_DOQ,
};

@interface AGDnsStamp : AGDnsXPCObject <NSSecureCoding>
/**
 * Protocol.
 */
@property(nonatomic) AGStampProtoType proto;
/**
 * Server numerical IP address, represented as a string.
 */
@property(nonatomic) NSString *serverAddr;
/**
 * Optional provider name (i.e. hostname in case of DoH/DoQ)
 * and optional port (written as ":<PortNumber>").
 * The grammar is something like this:
 * ```
 * providerName := [(ProviderName | Hostname)] [":" PortNumber]
 * PortNumber := DIGIT+
 * ```
 */
@property(nonatomic) NSString *providerName;
/**
 * Optional path (for DOH).
 */
@property(nonatomic) NSString *path;
/**
 * The DNSCrypt provider’s Ed25519 public key, as 32 raw bytes. Empty for other types.
 */
@property(nonatomic) NSData *serverPublicKey;
/**
 * Hash is the SHA256 digest of one of the TBS certificate found in the validation chain, typically
 * the certificate used to sign the resolver’s certificate. Multiple hashes can be provided for seamless
 * rotations.
 */
@property(nonatomic) NSArray<NSData *> *hashes;

/** Server properties */
/** Resolver does DNSSEC validation */
@property(nonatomic) BOOL dnssec;
/** Resolver does not record logs */
@property(nonatomic) BOOL noLog;
/** Resolver doesn't intentionally block domains */
@property(nonatomic) BOOL noFilter;

- (instancetype) init NS_UNAVAILABLE;

- (instancetype)initWithCoder:(NSCoder *)coder;

- (void)encodeWithCoder:(NSCoder *)coder;

/** Init a stamp from "sdns://" string */
- (instancetype) initWithString:(NSString *)stampStr error:(NSError **)error NS_SWIFT_NOTHROW;

/** Create a stamp from "sdns://" string */
+ (instancetype) stampWithString:(NSString *)stampStr error:(NSError **)error NS_SWIFT_NOTHROW;

/** A URL representation of this stamp which can be used as a valid AGDnsUpstream address */
@property(nonatomic, readonly) NSString *prettyUrl;

/** A URL representation of this stamp which is prettier, but can NOT be used as a valid AGDnsUpstream address */
@property(nonatomic, readonly) NSString *prettierUrl;

/** An "sdns://" string representation */
@property(nonatomic, readonly) NSString *stringValue;

@end

@interface AGDnsUtils : NSObject

/**
 * Checks if upstream is valid and available
 * @param opts Upstream options
 * @param ipv6Available Whether IPv6 is available (if true, bootstrapper is allowed to make AAAA queries)
 * @param offline Don't perform online upstream check
 * @return If it is, no error is returned. Otherwise this method returns an error with an explanation.
 */
+ (NSError *) testUpstream: (AGDnsUpstream *) opts ipv6Available: (BOOL) ipv6Available offline: (BOOL) offline;

@end
