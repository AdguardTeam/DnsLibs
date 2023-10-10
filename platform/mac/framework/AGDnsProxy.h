#import <Foundation/Foundation.h>

#import "AGDnsProxyEvents.h"

/**
 * @defgroup enums
 */

/**
 * DNS proxy error domain
 */
extern NSErrorDomain const AGDnsProxyErrorDomain;

/**
 * @ingroup enums
 * DNS error codes.
 *
 * Defines the different DNS error codes used in the application
 */
typedef NS_ENUM(NSInteger, AGDnsProxyInitError) {
    /** The DNS proxy is not set */
    AGDPE_PROXY_NOT_SET,
    /** The event loop is not set */
    AGDPE_EVENT_LOOP_NOT_SET,
    /** The provided address is invalid */
    AGDPE_INVALID_ADDRESS,
    /** The proxy is empty */
    AGDPE_EMPTY_PROXY,
    /** There is an error in the protocol */
    AGDPE_PROTOCOL_ERROR,
    /** Failed to initialize the listener */
    AGDPE_LISTENER_INIT_ERROR,
    /** The provided IPv4 address is invalid */
    AGDPE_INVALID_IPV4,
    /** The provided IPv6 address is invalid */
    AGDPE_INVALID_IPV6,
    /** Failed to initialize the upstream */
    AGDPE_UPSTREAM_INIT_ERROR,
    /** Failed to initialize the fallback filter */
    AGDPE_FALLBACK_FILTER_INIT_ERROR,
    /** Failed to load the filter */
    AGDPE_FILTER_LOAD_ERROR,
    /** The memory limit has been reached */
    AGDPE_MEM_LIMIT_REACHED,
    /** The filter ID is not unique */
    AGDPE_NON_UNIQUE_FILTER_ID,

    /** Failed to test the upstream */
    AGDPE_TEST_UPSTREAM_ERROR,
    /** Failed to initialize the proxy */
    AGDPE_PROXY_INIT_ERROR,
    /** Failed to initialize the listener during proxy initialization */
    AGDPE_PROXY_INIT_LISTENER_ERROR,
    /** Failed to initialize the helper during proxy initialization */
    AGDPE_PROXY_INIT_HELPER_ERROR,
    /** Failed to bind the helper during proxy initialization */
    AGDPE_PROXY_INIT_HELPER_BIND_ERROR,
};

/**
 * @ingroup enums
 * Logging levels.
 *
 * Defines the different logging levels used in the application.
 */
typedef NS_ENUM(NSInteger, AGLogLevel) {
    /** Error: Indicates an error that requires immediate attention */
    AGLL_ERR,
    /** Warning: Indicates a potential issue that may cause problems */
    AGLL_WARN,
    /** Information: Provides general information about the application state */
    AGLL_INFO,
    /** Debug: Contains detailed debugging information for developers */
    AGLL_DEBUG,
    /** Trace: Contains low-level tracing information for developers */
    AGLL_TRACE,
};


/**
 * @ingroup enums
 * Listener protocols.
 *
 * Defines the different listener protocols used in the application.
 */
typedef NS_ENUM(NSInteger, AGListenerProtocol) {
    /** User Datagram Protocol (UDP) */
    AGLP_UDP,
    /** Transmission Control Protocol (TCP) */
    AGLP_TCP,
};

/**
 * @ingroup enums
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

/**
 * @interface AGLogger
 * Class for configuring logging for DNS library.
 *
 * Provides a way to configure logging for the DNS library.
 * The logging level and the logging function can be set using the provided methods.
 */
@interface AGLogger : NSObject

/**
 * Set the default logging level
 *
 * @param level logging level to be set
 */
+ (void) setLevel: (AGLogLevel) level;

/**
 * A function that outputs a log message.
 *
 * This block is called when a log message needs to be output.
 * The message is already formatted, including the line terminator.
 *
 * @param level The log level of the message
 * @param msg The formatted log message
 * @param length The length of the log message
 */
typedef void (^logCallback)(AGLogLevel level, const char *msg, int length);

/**
 * Set log callback
 *
 * @param func logging function
 */
+ (void) setCallback: (logCallback) func;

@end

/**
 * @interface AGDnsUpstream
 *
 * Represents a DNS upstream server.
 */
@interface AGDnsUpstream : AGDnsXPCObject <NSSecureCoding>
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
@property(nonatomic) NSString *address;
/**
 * List of plain DNS servers.
 * List used to resolve the hostname in the upstream's address when necessary.
 * These servers will help establish the initial connection to the upstream DNS server
 * if its address is specified as a hostname.
 */
@property(nonatomic) NSArray<NSString *> *bootstrap;
/**
 * Upstream's IP address.
 * Pre-resolved IP address for the upstream server. If this field is specified, the @ref bootstrap
 * DNS servers won't be used for resolving the upstream's address.
 */
@property(nonatomic) NSData *serverIp;
/**
 * User-provided ID for this upstream
 */
@property(nonatomic) NSInteger id;
/**
 * Name of the network interface to route traffic through.
 * Optional on macOS, nil is default.
 * Required on iOS.
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

/**
 * @interface AGDns64Settings
 * Represents DNS64 settings for the DNS proxy.
 */
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

/**
 * @interface AGDnsProxySettingsOverrides
 * The subset of AGDnsProxyConfig available for overriding on a specific listener.
 */
@interface AGDnsProxySettingsOverrides : AGDnsXPCObject <NSSecureCoding>

/** Overrides AGDnsProxyConfig.block_ech if not nil */
@property(nonatomic) NSNumber *blockEch;

- (instancetype)initWithCoder:(NSCoder *)coder;

- (void)encodeWithCoder:(NSCoder *)coder;

- (NSString*)description;

@end

/**
 * @interface AGListenerSettings
 * Settings for a DNS proxy listener.
 */
@interface AGListenerSettings : AGDnsXPCObject <NSSecureCoding>

/**
 * The port to listen on
 * This is the address on which the listener will wait for incoming DNS queries.
 */
@property(nonatomic) NSString *address;

/**
 * The port to listen on.
 * This is the port on which the listener will wait for incoming DNS queries.
 */
@property(nonatomic) NSInteger port;

/**
 * The protocol to listen for
 */
@property(nonatomic) AGListenerProtocol proto;

/**
 * Whether the listener should keep the TCP connection open after sending the first response.
 * If set to true, the connection will not be closed immediately,
 * allowing for multiple requests and responses over the same connection.
 */
@property(nonatomic) BOOL persistent;

/**
 * Idle timeout.
 * Duration (in milliseconds) after which the listener should close the TCP connection if no
 * requests have been received. This setting helps to prevent idle connections from consuming resources.
 */
@property(nonatomic) NSInteger idleTimeoutMs;

/**
 * Overridden settings
 */
@property(nonatomic) AGDnsProxySettingsOverrides *settingsOverrides;

- (instancetype)initWithCoder:(NSCoder *)coder;

- (void)encodeWithCoder:(NSCoder *)coder;

- (NSString*)description;

@end

/**
 * @ingroup enums
 * Outbound proxy protocols.
 *
 * Defines the different outbound proxy protocols used in the application.
 */
typedef NS_ENUM(NSInteger, AGOutboundProxyProtocol) {
    /** Plain HTTP proxy */
    AGOPP_HTTP_CONNECT,
    /** HTTPS proxy */
    AGOPP_HTTPS_CONNECT,
    /** SOCKS4 proxy */
    AGOPP_SOCKS4,
    /** SOCKS5 proxy without UDP support */
    AGOPP_SOCKS5,
    /** SOCKS5 proxy with UDP support */
    AGOPP_SOCKS5_UDP,
};

/**
 * @interface AGOutboundProxyAuthInfo
 * Represents authentication information for an outbound proxy.
 */
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

/**
 * @interface AGOutboundProxySettings
 * Represents settings for an outbound proxy.
 */
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

/**
 * @interface AGDnsFilterParams
 * Represents the parameters for an individual filter used in the filter engine.
 */
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


/**
 * @interface AGDnsProxyConfig
 * Represents settings for the DNS proxy.
 *
 * Defines the various configuration options that can be used to specify the DNS proxy settings.
 */
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
 * If true, bootstrappers will fetch AAAA records
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
 * Maximum amount of time, in milliseconds, allowed for upstream exchange.
 * A timeout of 0 means "default".
 */
@property(nonatomic) NSUInteger upstreamTimeoutMs;
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

- (NSString *)description;

/**
 * Get default DNS proxy settings
 */
+ (instancetype) getDefault;
@end

/**
 * @ingroup enums
 * Rule generation options.
 *
 * Defines the different rule generation options used in the application.
 */
typedef NS_ENUM(NSUInteger, AGRuleGenerationOptions) {
    /** Add an $important modifier */
    AGRGOImportant = 1u << 0,
    /** Add a $dnstype modifier */
    AGRGODnstype = 1u << 1,
};

/**
 * @interface AGRuleTemplate
 * An object representing a template for generating DNS rules.
 */
@interface AGRuleTemplate : NSObject
- (NSString *)description; /**< String representation. */
/**
 * Generate a rule using this template and the specified options.
 * @param options Union of `AGRuleGenerationOptions` values
 * @return The resulting rule or `nil` on error
 */
- (NSString *)generateRuleWithOptions:(NSUInteger)options;
@end

/**
 * @interface AGFilteringLogAction
 * Provides a way to suggest rules based on filtering event.
 */
@interface AGFilteringLogAction : NSObject
@property(nonatomic) NSArray<AGRuleTemplate *> *templates; /**< A set of rule templates */
@property(nonatomic) NSUInteger allowedOptions; /**< Options that are allowed to be passed to `generate_rule` */
@property(nonatomic) NSUInteger requiredOptions; /**< Options that are required for the generated rule to be correct */
@property(nonatomic) BOOL blocking; /**< Whether something will be blocked or un-blocked as a result of this action */
/**
 * Suggest an action based on filtering event.
 * @param event Processed event
 * @return The action or nil on error
 */
+ (instancetype)actionFromEvent:(AGDnsRequestProcessedEvent *)event;
@end

/**
 * @interface AGDnsProxy
 * Represents a DNS proxy.
 *
 * Provides methods for provides management and interaction with proxy server.
 *
 * Usage example:
 * @code{.mm}
 * int main() {
 *     auto *listener = [[AGListenerSettings alloc] init];
 *     auto *handler = [[AGDnsProxyEvents alloc] init];
 *     NSError *error;
 *     auto *proxy = [[AGDnsProxy alloc] initWithConfig:config handler:handler error:&error];
 *     if (error || !proxy) {
 *         [proxy stop];
 *         return 1;
 *     }
 *     ...
 *     [proxy stop];
 *     return 0;
 * }
 * @endcode
 */
@interface AGDnsProxy : NSObject
/**
 * Initialize DNS proxy with the given configuration.
 *
 * @param config proxy configuration
 * @param events proxy events handler
 * @param error  error reference
 */
- (instancetype) initWithConfig: (AGDnsProxyConfig *) config
                        handler: (AGDnsProxyEvents *) events
                          error: (NSError **) error NS_SWIFT_NOTHROW;

/**
 * Process UDP/TCP packet payload.
 *
 * @param Packet data to process
 * @param completionHandler Completion handler
 * @return The response packet payload, or nil if nothing shoud be sent in response
 */
- (void) handlePacket: (NSData *) packet completionHandler: (void (^)(NSData *)) completionHandler;

/**
 * Stop DnsProxy.
 * @note Should be called before dealloc
 */
- (void) stop;

/**
* Check if string is a valid rule
* @param str string to check
* @return True if string is a valid rule, false otherwise
*/
+ (BOOL) isValidRule: (NSString *) str;

/**
 * Gets the library version
 * @return The DNS proxy library version
 */
+ (NSString *) libraryVersion;

@end

/**
 * @ingroup enums
 * Stamp protocol types.
 *
 * Defines the different stamp protocol types used in the application.
 */
typedef NS_ENUM(NSInteger, AGStampProtoType) {
    /** Plain DNS */
    AGSPT_PLAIN,
    /** DNSCrypt */
    AGSPT_DNSCRYPT,
    /** DNS-over-HTTPS */
    AGSPT_DOH,
    /** DNS-over-TLS */
    AGSPT_TLS,
    /** DNS-over-QUIC */
    AGSPT_DOQ,
};

/**
 * @interface AGDnsStamp
 * Represents a DNS stamp.
 */
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

/**
 * @interface AGDnsUtils
 * Represents  DNS utils
 */
@interface AGDnsUtils : NSObject

/**
 * Checks if upstream is valid and available
 * @param opts Upstream options
 * @param timeoutMs Upstream exchange timeout
 * @param ipv6Available If true, bootstrapper is allowed to make AAAA queries (Whether IPv6 is available)
 * @param offline If true, don't perform online upstream check
 * @return If it is, no error is returned. Otherwise this method returns an error with an explanation
 */
+ (NSError *)testUpstream:(AGDnsUpstream *)opts
                timeoutMs:(NSUInteger)timeoutMs
            ipv6Available:(BOOL)ipv6Available
                  offline:(BOOL)offline;

@end
