#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <assert.h>

#import "AGDnsProxy.h"

#include <ag_logger.h>
#include <dnsproxy.h>
#include <spdlog/sinks/base_sink.h>


static logCallback logFunc;

@implementation AGLogger
+ (void) setLevel: (AGLogLevel) level
{
    ag::set_default_log_level((ag::log_level)level);
}

+ (void) setCallback: (logCallback) func
{
    logFunc = func;
}
@end


class nslog_sink : public spdlog::sinks::base_sink<std::mutex> {
public:
    static ag::logger create(const std::string &logger_name) {
        return spdlog::default_factory::template create<nslog_sink>(logger_name);
    }

private:
    void sink_it_(const spdlog::details::log_msg &msg) override {
        spdlog::memory_buf_t formatted;
        this->formatter_->format(msg, formatted);
        if (logFunc != nil) {
            logFunc(formatted.data(), formatted.size());
        }
    }

    void flush_() override {}
};


#pragma pack(push,1)
struct iphdr {
#if BYTE_ORDER == LITTLE_ENDIAN
    u_int   ip_hl:4;        /* header length */
    u_int   ip_v:4;         /* version */
#endif
#if BYTE_ORDER == BIG_ENDIAN
    u_int   ip_v:4;         /* version */
    u_int   ip_hl:4;        /* header length */
#endif
    uint8_t ip_tos;         /* type of service */
    uint16_t    ip_len;         /* total length */
    uint16_t    ip_id;          /* identification */
    uint16_t    ip_off;         /* fragment offset field */
    uint8_t ip_ttl;         /* time to live */
    uint8_t ip_p;           /* protocol */
    uint16_t    ip_sum;         /* checksum */
    struct  in_addr ip_src;
    struct  in_addr ip_dst; /* source and dest address */
};

struct udphdr {
    uint16_t    uh_sport;       /* source port */
    uint16_t    uh_dport;       /* destination port */
    uint16_t    uh_ulen;        /* udp length */
    uint16_t    uh_sum;         /* udp checksum */
};
#pragma pack(pop)

static uint16_t ip_checksum(const void *ip_header, uint32_t header_length) {
    uint32_t checksum = 0;
    const uint16_t *data = (uint16_t *)ip_header;
    while (header_length > 1) {
        checksum += *data;
        data++;
        header_length -= 2;
    }
    if (header_length > 0) {
        checksum += *(uint8_t*)data;
    }

    checksum = (checksum >> 16) + (checksum & 0xffff);
    checksum = (checksum >> 16) + (checksum & 0xffff);

    return ~checksum & 0xffff;
}

static uint16_t checksum(const void *buf, size_t len, uint32_t sum) {
    uint32_t i;
    for (i = 0; i < (len & ~1U); i += 2) {
        sum += (uint16_t)ntohs(*((uint16_t *)((uint8_t*)buf + i)));
        if (sum > 0xFFFF) {
            sum -= 0xFFFF;
        }
    }

    if (i < len) {
        sum += ((uint8_t*)buf)[i] << 8;
        if (sum > 0xFFFF) {
            sum -= 0xFFFF;
        }
    }

    return sum;
}

static uint16_t udp_checksum(const struct iphdr *ip_header, const struct udphdr *udp_header,
        const void *buf, size_t len) {
    uint32_t sum = ip_header->ip_p + (uint32_t)ntohs(udp_header->uh_ulen);
    sum = checksum(&ip_header->ip_src, 2 * sizeof(ip_header->ip_src), sum);
    sum = checksum(buf, len, sum);
    sum = checksum(udp_header, sizeof(*udp_header), sum);
    sum = ~sum & 0xFFFF;
    return htons(sum);
}

static NSData *create_response_packet(const struct iphdr *ip_header, const struct udphdr *udp_header,
        const std::vector<uint8_t> &payload) {
    struct udphdr reverse_udp_header = {};
    reverse_udp_header.uh_sport = udp_header->uh_dport;
    reverse_udp_header.uh_dport = udp_header->uh_sport;
    reverse_udp_header.uh_ulen = htons(sizeof(reverse_udp_header) + payload.size());

    struct iphdr reverse_ip_header = {};
    reverse_ip_header.ip_v = ip_header->ip_v;
    reverse_ip_header.ip_hl = 5; // ip header without options
    reverse_ip_header.ip_tos = ip_header->ip_tos;
    reverse_ip_header.ip_len = htons(ntohs(reverse_udp_header.uh_ulen) + reverse_ip_header.ip_hl * 4);
    reverse_ip_header.ip_id = ip_header->ip_id;
    reverse_ip_header.ip_ttl = ip_header->ip_ttl;
    reverse_ip_header.ip_p = ip_header->ip_p;
    reverse_ip_header.ip_src = ip_header->ip_dst;
    reverse_ip_header.ip_dst = ip_header->ip_src;

    reverse_ip_header.ip_sum = ip_checksum(&reverse_ip_header, sizeof(reverse_ip_header));
    reverse_udp_header.uh_sum = udp_checksum(&reverse_ip_header, &reverse_udp_header,
        payload.data(), payload.size());

    NSMutableData *reverse_packet = [[NSMutableData alloc] initWithCapacity: reverse_ip_header.ip_len];
    [reverse_packet appendBytes: &reverse_ip_header length: sizeof(reverse_ip_header)];
    [reverse_packet appendBytes: &reverse_udp_header length: sizeof(reverse_udp_header)];
    [reverse_packet appendBytes: payload.data() length: payload.size()];

    return reverse_packet;
}


@implementation AGDnsUpstream
- (instancetype) initWithNative: (const ag::upstream::options *) settings
{
    self = [super init];
    _address = [NSString stringWithUTF8String: settings->address.c_str()];
    NSMutableArray<NSString *> *bootstrap =
        [[NSMutableArray alloc] initWithCapacity: settings->bootstrap.size()];
    for (const std::string &server : settings->bootstrap) {
        [bootstrap addObject: [NSString stringWithUTF8String: server.c_str()]];
    }
    _bootstrap = bootstrap;
    _timeoutMs = settings->timeout.count();
    return self;
}

- (instancetype) initWithAddress: (NSString *) address
        bootstrap: (NSArray<NSString *> *) bootstrap
        timeoutMs: (NSInteger) timeoutMs
        serverIp: (NSData *) serverIp
{
    self = [super init];
    _address = address;
    _bootstrap = bootstrap;
    _timeoutMs = timeoutMs;
    _serverIp = serverIp;
    return self;
}
@end

@implementation AGDns64Settings
- (instancetype) initWithNative: (const ag::dns64_settings *) settings
{
    self = [super init];
    _upstream = [[AGDnsUpstream alloc] initWithNative: &settings->upstream_settings];
    _maxTries = settings->max_tries;
    _waitTimeMs = settings->wait_time.count();
    return self;
}

- (instancetype) initWithUpstream: (AGDnsUpstream *) upstream
                         maxTries: (NSInteger) maxTries waitTimeMs: (NSInteger) waitTimeMs
{
    self = [super init];
    _upstream = upstream;
    _maxTries = maxTries;
    _waitTimeMs = waitTimeMs;
    return self;
}

@end

@implementation AGListenerSettings
- (instancetype)initWithNative:(const ag::listener_settings *)settings
{
    self = [super init];
    _address = [NSString stringWithUTF8String:settings->address.c_str()];
    _port = settings->port;
    _proto = (AGListenerProtocol) ((NSInteger) settings->protocol);
    _persistent = settings->persistent;
    _idleTimeoutMs = settings->idle_timeout.count();
    return self;
}

- (instancetype)initWithAddress:(NSString *)address
                           port:(NSInteger)port
                          proto:(AGListenerProtocol)proto
                     persistent:(BOOL)persistent
                  idleTimeoutMs:(NSInteger)idleTimeoutMs
{
    self = [super init];
    _address = address;
    _port = port;
    _proto = proto;
    _persistent = persistent;
    _idleTimeoutMs = idleTimeoutMs;
    return self;
}
@end

@implementation AGDnsProxyConfig

- (instancetype) initWithNative: (const ag::dnsproxy_settings *) settings
{
    self = [super init];
    NSMutableArray<AGDnsUpstream *> *upstreams =
        [[NSMutableArray alloc] initWithCapacity: settings->upstreams.size()];
    for (const ag::upstream::options &us : settings->upstreams) {
        [upstreams addObject: [[AGDnsUpstream alloc] initWithNative: &us]];
    }
    _upstreams = upstreams;
    _filters = nil;
    _blockedResponseTtlSecs = settings->blocked_response_ttl_secs;
    if (settings->dns64.has_value()) {
        _dns64Settings = [[AGDns64Settings alloc] initWithNative: &settings->dns64.value()];
    }
    NSMutableArray<AGListenerSettings *> *listeners =
            [[NSMutableArray alloc] initWithCapacity: settings->listeners.size()];
    for (const ag::listener_settings &ls : settings->listeners) {
        [listeners addObject: [[AGListenerSettings alloc] initWithNative: &ls]];
    }
    _listeners = listeners;
    _ipv6Available = settings->ipv6_available;
    _blockIpv6 = settings->block_ipv6;
    return self;
}

- (instancetype) initWithUpstreams: (NSArray<AGDnsUpstream *> *) upstreams
        filters: (NSDictionary<NSNumber *,NSString *> *) filters
        blockedResponseTtlSecs: (NSInteger) blockedResponseTtlSecs
        dns64Settings: (AGDns64Settings *) dns64Settings
        listeners: (NSArray<AGListenerSettings *> *) listeners
        ipv6Available: (BOOL) ipv6Available
        blockIpv6: (BOOL) blockIpv6;
{
    const ag::dnsproxy_settings &defaultSettings = ag::dnsproxy_settings::get_default();
    self = [self initWithNative: &defaultSettings];
    if (upstreams != nil) {
        _upstreams = upstreams;
    }
    _filters = filters;
    if (blockedResponseTtlSecs != 0) {
        _blockedResponseTtlSecs = blockedResponseTtlSecs;
    }
    _dns64Settings = dns64Settings;
    _listeners = listeners;
    _ipv6Available = ipv6Available;
    _blockIpv6 = blockIpv6;
    return self;
}

+ (instancetype) getDefault
{
    const ag::dnsproxy_settings &defaultSettings = ag::dnsproxy_settings::get_default();
    return [[AGDnsProxyConfig alloc] initWithNative: &defaultSettings];
}
@end

@implementation AGDnsRequestProcessedEvent
- (instancetype) init: (ag::dns_request_processed_event &)event
{
    _domain = [NSString stringWithUTF8String: event.domain.c_str()];
    _type = [NSString stringWithUTF8String: event.type.c_str()];
    _startTime = event.start_time;
    _elapsed = event.elapsed;
    _answer = [NSString stringWithUTF8String: event.answer.c_str()];
    _upstreamAddr = [NSString stringWithUTF8String: event.upstream_addr.c_str()];
    _bytesSent = event.bytes_sent;
    _bytesReceived = event.bytes_received;

    NSMutableArray<NSString *> *rules =
        [[NSMutableArray alloc] initWithCapacity: event.rules.size()];
    NSMutableArray<NSNumber *> *filterListIds =
        [[NSMutableArray alloc] initWithCapacity: event.rules.size()];
    for (size_t i = 0; i < event.rules.size(); ++i) {
        [rules addObject: [NSString stringWithUTF8String: event.rules[i].c_str()]];
        [filterListIds addObject: [NSNumber numberWithInteger: event.filter_list_ids[i]]];
    }
    _rules = rules;
    _filterListIds = filterListIds;

    _whitelist = event.whitelist;
    _error = [NSString stringWithUTF8String: event.error.c_str()];

    return self;
}
@end

@implementation AGDnsProxyEvents
@end

@implementation AGDnsProxy {
    ag::dnsproxy proxy;
    ag::logger log;
    AGDnsProxyEvents *events;
}

- (void) dealloc
{
    self->proxy.deinit();
}

static SecCertificateRef convertCertificate(const std::vector<uint8_t> &cert) {
    NSData *data = [NSData dataWithBytesNoCopy: (void *)cert.data() length: cert.size() freeWhenDone: NO];
    CFDataRef certRef = (__bridge CFDataRef)data;
    return SecCertificateCreateWithData(NULL, (CFDataRef)certRef);
}

static std::string getTrustCreationErrorStr(OSStatus status) {
#if !TARGET_OS_IPHONE || (IOS_VERSION_MAJOR >= 11 && IOS_VERSION_MINOR >= 3)
    CFStringRef err = SecCopyErrorMessageString(status, NULL);
    return [(__bridge NSString *)err UTF8String];
#else
    return AG_FMT("Failed to create trust object from chain: {}", status);
#endif
}

- (std::optional<std::string>) verifyCertificate: (ag::certificate_verification_event *) event
{
    tracelog(self->log, "[Verification] App callback");

    size_t chainLength = event->chain.size() + 1;
    SecCertificateRef chain[chainLength];

    chain[0] = convertCertificate(event->certificate);
    if (chain[0] == NULL) {
        dbglog(self->log, "[Verification] Failed to create certificate object");
        return "Failed to create certificate object";
    }

    for (size_t i = 0; i < event->chain.size(); ++i) {
        chain[i + 1] = convertCertificate(event->chain[i]);
        if (chain[i + 1] == NULL) {
            dbglog(self->log, "[Verification] Failed to create certificate object");
            return "Failed to create certificate object";
        }
    }

    NSMutableArray *trustArray = [[NSMutableArray alloc] initWithCapacity: chainLength];
    for (size_t i = 0; i < chainLength; ++i) {
        [trustArray addObject: (__bridge id _Nonnull)chain[i]];
    }

    SecPolicyRef policy = SecPolicyCreateBasicX509();
    SecTrustRef trust;
    OSStatus status = SecTrustCreateWithCertificates((__bridge CFTypeRef)trustArray, policy, &trust);
    if (policy) {
        CFRelease(policy);
    }

    if (status != errSecSuccess) {
        std::string err = getTrustCreationErrorStr(status);
        dbglog(self->log, "[Verification] Failed to create trust object from chain: {}", err);
        return err;
    }

    SecTrustSetAnchorCertificates(trust, (CFArrayRef) trustArray );
    SecTrustSetAnchorCertificatesOnly(trust, YES);
    SecTrustResultType trustResult;
    SecTrustEvaluate(trust, &trustResult);

    // Unspecified also stands for valid: https://developer.apple.com/library/archive/qa/qa1360/_index.html
    if (trustResult == kSecTrustResultUnspecified || trustResult == kSecTrustResultProceed) {
        dbglog(self->log, "[Verification] Succeeded");
        return std::nullopt;
    }

    std::string errStr;
    switch (trustResult) {
    case kSecTrustResultDeny:
        errStr = "The user specified that the certificate should not be trusted";
        break;
    case kSecTrustResultRecoverableTrustFailure:
        errStr = "Trust is denied, but recovery may be possible";
        break;
    case kSecTrustResultFatalTrustFailure:
        errStr = "Trust is denied and no simple fix is available";
        break;
    case kSecTrustResultOtherError:
        errStr = "A value that indicates a failure other than trust evaluation";
        break;
    case kSecTrustResultInvalid:
        errStr = "An indication of an invalid setting or result";
        break;
    default:
        errStr = AG_FMT("Unknown error code: {}", trustResult);
        break;
    }

    dbglog(self->log, "[Verification] Failed to verify: {}", errStr);
    return errStr;
}

- (instancetype) initWithConfig: (AGDnsProxyConfig *) config
        handler: (AGDnsProxyEvents *)handler
{
    ag::set_logger_factory_callback(nslog_sink::create);
    self->log = ag::create_logger("AGDnsProxy");

    infolog(self->log, "Initializing dns proxy...");

    ag::dnsproxy_settings settings = ag::dnsproxy_settings::get_default();
    if (config.upstreams != nil) {
        settings.upstreams.clear();
        settings.upstreams.reserve([config.upstreams count]);
        for (AGDnsUpstream *upstream in config.upstreams) {
            std::vector<std::string> bootstrap;
            if (upstream.bootstrap != nil) {
                bootstrap.reserve([upstream.bootstrap count]);
                for (NSString *server in upstream.bootstrap) {
                    bootstrap.emplace_back([server UTF8String]);
                }
            }
            ag::ip_address_variant addr;
            if (upstream.serverIp != nil && [upstream.serverIp length] == 4) {
                addr.emplace<ag::uint8_array<4>>();
                std::memcpy(std::get<ag::uint8_array<4>>(addr).data(),
                    [upstream.serverIp bytes], [upstream.serverIp length]);
            } else if (upstream.serverIp != nil && [upstream.serverIp length] == 16) {
                addr.emplace<ag::uint8_array<16>>();
                std::memcpy(std::get<ag::uint8_array<16>>(addr).data(),
                    [upstream.serverIp bytes], [upstream.serverIp length]);
            } else {
                addr.emplace<std::monostate>();
            }
            settings.upstreams.emplace_back(
                ag::upstream::options{[upstream.address UTF8String], std::move(bootstrap),
                                      std::chrono::milliseconds(upstream.timeoutMs), addr });
        }
    }

    settings.blocked_response_ttl_secs = config.blockedResponseTtlSecs;

    if (config.filters != nil) {
        settings.filter_params.filters.reserve([config.filters count]);
        for (NSNumber *key in config.filters) {
            const char *filterPath = [[config.filters objectForKey: key] UTF8String];
            dbglog(self->log, "Filter id={} path={}", [key intValue], filterPath);
            settings.filter_params.filters.emplace_back(
                ag::dnsfilter::filter_params{ (uint32_t)[key intValue], filterPath });
        }
    }

    void *obj = (__bridge void *)self;
    self->events = handler;
    ag::dnsproxy_events native_events = {};
    if (handler != nil && handler.onRequestProcessed != nil) {
         native_events.on_request_processed =
            [obj] (ag::dns_request_processed_event event) {
                AGDnsProxy *sself = (__bridge AGDnsProxy *)obj;
                sself->events.onRequestProcessed([[AGDnsRequestProcessedEvent alloc] init: event]);
            };
    }
    native_events.on_certificate_verification =
        [obj] (ag::certificate_verification_event event) -> std::optional<std::string> {
            AGDnsProxy *sself = (__bridge AGDnsProxy *)obj;
            return [sself verifyCertificate: &event];
        };

    if (config.dns64Settings != nil) {
        const AGDnsUpstream * const upstream = config.dns64Settings.upstream;
        if (upstream == nil) {
            dbglog(self->log, "DNS64 upstream is nil");
        } else {
            std::vector<std::string> bootstrap;
            bootstrap.reserve([upstream.bootstrap count]);

            for (NSString *server in upstream.bootstrap) {
                bootstrap.emplace_back([server UTF8String]);
            }

            settings.dns64 = ag::dns64_settings{
                    .upstream_settings = {[upstream.address UTF8String],
                            std::move(bootstrap),
                            std::chrono::milliseconds(upstream.timeoutMs)},
                    .wait_time = std::chrono::milliseconds(config.dns64Settings.waitTimeMs),
                    .max_tries = config.dns64Settings.maxTries > 0
                                 ? static_cast<uint32_t>(config.dns64Settings.maxTries) : 0,
            };
        }
    }

    if (config.listeners != nil) {
        settings.listeners.clear();
        settings.listeners.reserve([config.listeners count]);

        for (AGListenerSettings *listener in config.listeners) {
            settings.listeners.push_back({
                [listener.address UTF8String],
                (uint16_t) listener.port,
                (ag::listener_protocol) ((int) listener.proto),
                (bool) listener.persistent,
                std::chrono::milliseconds(listener.idleTimeoutMs),
            });
        }
    }

    settings.ipv6_available = config.ipv6Available;
    settings.block_ipv6 = config.blockIpv6;

    if (!self->proxy.init(std::move(settings), std::move(native_events))) {
        errlog(self->log, "Failed to initialize core proxy module");
        return nil;
    }

    infolog(self->log, "Dns proxy initialized");

    return self;
}

- (NSData *) handlePacket: (NSData *) packet
{
    struct iphdr *ip_header = (struct iphdr *)packet.bytes;
    // @todo: handle tcp packets also
    if (ip_header->ip_p != IPPROTO_UDP) {
        return nil;
    }

    NSInteger ip_header_length = ip_header->ip_hl * 4;
    struct udphdr *udp_header = (struct udphdr *)((Byte *)packet.bytes + ip_header_length);
    NSInteger udp_header_length = ip_header_length + sizeof(struct udphdr);
    dbglog(self->log, "{}:{} -> {}:{}"
        , inet_ntoa(ip_header->ip_src), ntohs(udp_header->uh_sport)
        , inet_ntoa(ip_header->ip_dst), ntohs(udp_header->uh_dport));

    ag::uint8_view payload = { (uint8_t*)packet.bytes + udp_header_length, packet.length - udp_header_length };
    std::vector<uint8_t> response = self->proxy.handle_message(payload);
    return create_response_packet(ip_header, udp_header, response);
}

+ (BOOL) isValidRule: (NSString *) str
{
    return ag::dnsfilter::is_valid_rule({ [str UTF8String] });
}

@end
