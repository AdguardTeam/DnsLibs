#import "AGDnsProxy.h"
#import <TargetConditionals.h>
#if !TARGET_OS_IPHONE
#import "NSTask+AGUtils.h"
#endif

#pragma GCC visibility push(hidden)
#import <sys/socket.h>
#import <netinet/in.h>
#import <arpa/inet.h>
#import <resolv.h>
#import <poll.h>
#import <cassert>
#import <optional>
#import <string>
#import <magic_enum/magic_enum.hpp>

#import "common/cesu8.h"
#import "common/error.h"
#import "common/logger.h"
#import "dns/proxy/dnsproxy.h"
#import "dns/upstream/upstream_utils.h"
#pragma GCC visibility pop

#import "AGDnsXPCObject.h"

using namespace ag;
using namespace ag::dns;

#if TARGET_OS_IPHONE
static constexpr size_t FILTER_PARAMS_MEM_LIMIT_BYTES = 8 * 1024 * 1024;
#endif // TARGET_OS_IPHONE

static constexpr int BINDFD_WAIT_MS = 10000;
static constexpr int ERR_BIND_IN_USE = 14;

static const char *IS_DNS_QUEUE_KEY = "isAGDnsProxyQueue";

/**
 * @param str an STL string
 * @return an NSString converted from the C++ string
 */
static NSString *convert_string(const std::string &str) {
    return @(ag::utf8_to_cesu8(str).c_str());
}

static std::string convert_string(NSString *str) {
    if (auto *s = str.UTF8String) {
        return s;
    }
    return "";
}

NSErrorDomain const AGDnsProxyErrorDomain = @"com.adguard.dnsproxy";

@implementation AGDnsLogger
+ (void) setLevel: (AGDnsLogLevel) level
{
    Logger::set_log_level((LogLevel)level);
}

+ (void) setCallback: (logCallback) func
{
    if (func) {
        Logger::set_callback([func](LogLevel level, std::string_view message) {
            @autoreleasepool {
                func((AGDnsLogLevel) level, message.data(), message.size());
            }
        });
    } else {
        Logger::set_callback(nullptr);
    }
}
@end


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

// Home-made IPv6 header struct
struct iphdr6 {
#if BYTE_ORDER == LITTLE_ENDIAN
    uint32_t ip6_unused:28;    /* traffic class and flow label */
    uint32_t ip6_v:4;          /* version (constant 0x6) */
#endif
#if BYTE_ORDER == BIG_ENDIAN
    uint32_t ip6_v:4;          /* version (constant 0x6) */
    uint32_t ip6_unused:28;    /* traffic class and flow label */
#endif
    uint16_t ip6_pl;    /* payload length */
    uint8_t ip6_nh;     /* next header (same as protocol) */
    uint8_t ip6_hl;     /* hop limit */
    in6_addr_t ip6_src; /* source address */
    in6_addr_t ip6_dst; /* destination address */
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

    return (uint16_t) (~checksum & 0xffff);
}

// Compute sum of buf as if it is a vector of uint16_t, padding with zeroes at the end if needed
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

    return (uint16_t) sum;
}

static uint16_t udp_checksum(const struct iphdr *ip_header, const struct udphdr *udp_header,
        const void *buf, size_t len) {
    uint16_t sum = ip_header->ip_p + ntohs(udp_header->uh_ulen);
    sum = checksum(&ip_header->ip_src, 2 * sizeof(ip_header->ip_src), sum);
    sum = checksum(buf, len, sum);
    sum = checksum(udp_header, sizeof(*udp_header), sum);
    // 0xffff should be transmitted as is
    if (sum != 0xffff) {
        sum = ~sum;
    }
    return htons(sum);
}

static uint16_t udp_checksum_v6(const struct iphdr6 *ip6_header,
                                const struct udphdr *udp_header,
                                const void *buf, size_t len) {
    uint16_t sum = ip6_header->ip6_nh + ntohs(udp_header->uh_ulen);
    sum = checksum(&ip6_header->ip6_src, 2 * sizeof(ip6_header->ip6_src), sum);
    sum = checksum(buf, len, sum);
    sum = checksum(udp_header, sizeof(*udp_header), sum);
    // 0xffff should be transmitted as is
    if (sum != 0xffff) {
        sum = ~sum;
    }
    return htons(sum);
}

static CFDataRef create_response_packet(const struct iphdr *ip_header, const struct udphdr *udp_header,
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

    return (__bridge_retained CFDataRef) reverse_packet;
}

static CFDataRef create_response_packet_v6(const struct iphdr6 *ip6_header, const struct udphdr *udp_header,
        const std::vector<uint8_t> &payload) {
    struct udphdr resp_udp_header = {};
    resp_udp_header.uh_sport = udp_header->uh_dport;
    resp_udp_header.uh_dport = udp_header->uh_sport;
    resp_udp_header.uh_ulen = htons(sizeof(resp_udp_header) + payload.size());

    struct iphdr6 resp_ip6_header = *ip6_header;
    resp_ip6_header.ip6_src = ip6_header->ip6_dst;
    resp_ip6_header.ip6_dst = ip6_header->ip6_src;
    resp_ip6_header.ip6_pl = resp_udp_header.uh_ulen;

    resp_udp_header.uh_sum = udp_checksum_v6(&resp_ip6_header, &resp_udp_header,
                                             payload.data(), payload.size());

    NSUInteger packet_length = sizeof(resp_ip6_header) + resp_ip6_header.ip6_pl;
    NSMutableData *response_packet = [[NSMutableData alloc] initWithCapacity: packet_length];
    [response_packet appendBytes: &resp_ip6_header length: sizeof(resp_ip6_header)];
    [response_packet appendBytes: &resp_udp_header length: sizeof(resp_udp_header)];
    [response_packet appendBytes: payload.data() length: payload.size()];

    return (__bridge_retained CFDataRef) response_packet;
}

static ServerStamp convert_stamp(AGDnsStamp *stamp) {
    ServerStamp native{};
    native.proto = (StampProtoType) stamp.proto;
    if (stamp.serverAddr) {
        native.server_addr_str = stamp.serverAddr.UTF8String;
    }
    if (stamp.providerName) {
        native.provider_name = stamp.providerName.UTF8String;
    }
    if (stamp.path) {
        native.path = stamp.path.UTF8String;
    }
    if (auto *pubkey = stamp.serverPublicKey; pubkey) {
        native.server_pk.assign((uint8_t *) pubkey.bytes, (uint8_t *) pubkey.bytes + pubkey.length);
    }
    if (stamp.hashes) {
        for (NSData *hash in stamp.hashes) {
            native.hashes.emplace_back((uint8_t *) hash.bytes, (uint8_t *) hash.bytes + hash.length);
        }
    }
    if (stamp.properties != nil) {
        native.props = (ServerInformalProperties)[stamp.properties unsignedLongLongValue];
    }

    return native;
}

@implementation AGDnsUpstream

+ (BOOL)supportsSecureCoding {
    return YES;
}

- (instancetype) initWithNative: (const UpstreamOptions *) settings
{
    self = [super init];
    _address = convert_string(settings->address);
    _id = settings->id;
    NSMutableArray<NSString *> *bootstrap =
        [[NSMutableArray alloc] initWithCapacity: settings->bootstrap.size()];
    for (const std::string &server : settings->bootstrap) {
        [bootstrap addObject: convert_string(server)];
    }
    _bootstrap = bootstrap;
    if (const std::string *name = std::get_if<std::string>(&settings->outbound_interface)) {
        _outboundInterfaceName = convert_string(*name);
    }
    NSMutableArray<NSString *> *fingerprints =
            [[NSMutableArray alloc] initWithCapacity: settings->fingerprints.size()];
    for (const std::string &fp : settings->fingerprints) {
        [fingerprints addObject: convert_string(fp)];
    }
    _fingerprints = fingerprints;
    return self;
}

- (instancetype)initWithCoder:(NSCoder *)coder {
    self = [super init];
    if (self) {
        _address = [coder decodeObjectOfClass:NSString.class forKey:@"_address"];
        _bootstrap = [coder decodeObjectOfClasses:[[NSSet alloc] initWithObjects:NSArray.class, NSString.class, nil] forKey:@"_bootstrap"];
        _serverIp = [coder decodeObjectOfClass:NSData.class forKey:@"_serverIp"];
        _id = [coder decodeInt64ForKey:@"_id"];
        _outboundInterfaceName = [coder decodeObjectOfClass:NSString.class forKey:@"_outboundInterfaceName"];
        _fingerprints = [coder decodeObjectOfClasses:[[NSSet alloc] initWithObjects:NSArray.class, NSString.class, nil] forKey:@"_fingerprints"];
    }

    return self;
}

- (void)encodeWithCoder:(NSCoder *)coder {
    [coder encodeObject:self.address forKey:@"_address"];
    [coder encodeObject:self.bootstrap forKey:@"_bootstrap"];
    [coder encodeObject:self.serverIp forKey:@"_serverIp"];
    [coder encodeInt64:self.id forKey:@"_id"];
    [coder encodeObject:self.outboundInterfaceName forKey:@"_outboundInterfaceName"];
    [coder encodeObject:self.fingerprints forKey:@"_fingerprints"];
}

- (NSString*)description {
    return [NSString stringWithFormat:
            @"[(%p)AGDnsUpstream: address=%@, bootstrap=(%@), serverIp=%@, id=%ld]",
            self, _address, [_bootstrap componentsJoinedByString:@", "], [[NSString alloc] initWithData:_serverIp encoding:NSUTF8StringEncoding], _id];
}

@end

@implementation AGDns64Settings

+ (BOOL)supportsSecureCoding {
    return YES;
}

- (instancetype) initWithNative: (const Dns64Settings *) settings
{
    self = [super init];
    NSMutableArray<AGDnsUpstream *> *upstreams = [[NSMutableArray alloc] initWithCapacity: settings->upstreams.size()];
    for (auto &us : settings->upstreams) {
        [upstreams addObject: [[AGDnsUpstream alloc] initWithNative: &us]];
    }
    _upstreams = upstreams;
    _maxTries = settings->max_tries;
    _waitTimeMs = settings->wait_time.count();
    return self;
}

- (instancetype)initWithCoder:(NSCoder *)coder {
    self = [super init];
    if (self) {
        _upstreams = [coder decodeObjectOfClasses:[[NSSet alloc] initWithObjects:NSArray.class, AGDnsUpstream.class, nil] forKey:@"_upstreams"];
        _maxTries = [coder decodeInt64ForKey:@"_maxTries"];
        _waitTimeMs = [coder decodeInt64ForKey:@"_waitTimeMs"];
    }

    return self;
}

- (void)encodeWithCoder:(NSCoder *)coder {
    [coder encodeObject:self.upstreams forKey:@"_upstreams"];
    [coder encodeInt64:self.maxTries forKey:@"_maxTries"];
    [coder encodeInt64:self.waitTimeMs forKey:@"_waitTimeMs"];
}

- (NSString*)description {
    return [NSString stringWithFormat:
            @"[(%p)AGDns64Settings: waitTimeMs=%ld, upstreams=%@]",
            self, _waitTimeMs, _upstreams];
}

@end

@implementation AGDnsProxySettingsOverrides

+ (BOOL)supportsSecureCoding {
    return YES;
}

- (instancetype)initWithNative:(const ProxySettingsOverrides *)settings {
    self = [super init];
    if (settings->block_ech.has_value()) {
        _blockEch = [NSNumber numberWithBool:settings->block_ech.value()];
    }
    return self;
}

- (instancetype)initWithCoder:(NSCoder *)coder {
    self = [super init];
    if (self) {
        _blockEch = [coder decodeObjectOfClass:NSNumber.class forKey:@"_blockEch"];
    }
    return self;
}

- (void)encodeWithCoder:(NSCoder *)coder {
    [coder encodeObject:self.blockEch forKey:@"_blockEch"];
}

- (NSString *)description {
    return [NSString stringWithFormat:@"[(%p)AGDnsProxySettingsOverrides: blockEch=%@]", self, _blockEch];
}

@end

@implementation AGDnsListenerSettings

+ (BOOL)supportsSecureCoding {
    return YES;
}

- (instancetype)initWithNative:(const ListenerSettings *)settings
{
    self = [super init];
    _address = convert_string(settings->address);
    _port = settings->port;
    _proto = (AGDnsListenerProtocol) settings->protocol;
    _persistent = settings->persistent;
    _idleTimeoutMs = settings->idle_timeout.count();
    _settingsOverrides = [[AGDnsProxySettingsOverrides alloc] initWithNative:&settings->settings_overrides];
    return self;
}

- (instancetype)initWithCoder:(NSCoder *)coder {
    self = [super init];
    if (self) {
        _address = [coder decodeObjectOfClass:NSString.class forKey:@"_address"];
        _port = [coder decodeInt64ForKey:@"_port"];
        _proto = (AGDnsListenerProtocol) [coder decodeIntForKey:@"_proto"];
        _persistent = [coder decodeBoolForKey:@"_persistent"];
        _idleTimeoutMs = [coder decodeInt64ForKey:@"_idleTimeoutMs"];
        _settingsOverrides = [coder decodeObjectOfClass:AGDnsProxySettingsOverrides.class forKey:@"_settingsOverrides"];
    }

    return self;
}

- (void)encodeWithCoder:(NSCoder *)coder {
    [coder encodeObject:self.address forKey:@"_address"];
    [coder encodeInt64:self.port forKey:@"_port"];
    [coder encodeInt:self.proto forKey:@"_proto"];
    [coder encodeBool:self.persistent forKey:@"_persistent"];
    [coder encodeInt64:self.idleTimeoutMs forKey:@"_idleTimeoutMs"];
    [coder encodeObject:self.settingsOverrides forKey:@"_settingsOverrides"];
}

- (NSString*)description {
    return [NSString stringWithFormat:
            @"[(%p)AGListenerSettings: address=%@, port=%ld, proto=%ld, settingsOverrides=[%@]]",
            self, _address, _port, _proto, (_settingsOverrides == nil) ? @"nil" : [_settingsOverrides description]];
}

@end

@implementation AGDnsOutboundProxyAuthInfo

+ (BOOL)supportsSecureCoding {
    return YES;
}

- (instancetype) initWithNative: (const OutboundProxyAuthInfo *)info
{
    self = [super init];
    if (self) {
        _username = convert_string(info->username);
        _password = convert_string(info->password);
    }
    return self;
}

- (instancetype) initWithCoder: (NSCoder *)coder
{
    self = [super init];
    if (self) {
        _username = [coder decodeObjectOfClass:NSString.class forKey:@"_username"];
        _password = [coder decodeObjectOfClass:NSString.class forKey:@"_password"];
    }
    return self;
}

- (void)encodeWithCoder:(NSCoder *)coder
{
    [coder encodeObject:self.username forKey:@"_username"];
    [coder encodeObject:self.password forKey:@"_password"];
}

- (NSString*)description {
    return [NSString stringWithFormat:@"[(%p)AGOutboundProxyAuthInfo: username=%@]", self, _username];
}

@end

@implementation AGDnsOutboundProxySettings

+ (BOOL)supportsSecureCoding {
    return YES;
}

- (instancetype) initWithNative: (const OutboundProxySettings *)settings
{
    self = [super init];
    if (self) {
        _protocol = (AGDnsOutboundProxyProtocol)settings->protocol;
        _address = convert_string(settings->address);
        _port = settings->port;
        NSMutableArray<NSString *> *bootstrap =
                [[NSMutableArray alloc] initWithCapacity: settings->bootstrap.size()];
        for (const std::string &server : settings->bootstrap) {
            [bootstrap addObject: convert_string(server)];
        }
        _bootstrap = bootstrap;
        if (settings->auth_info.has_value()) {
            _authInfo = [[AGDnsOutboundProxyAuthInfo alloc] initWithNative: &settings->auth_info.value()];
        }
        _trustAnyCertificate = settings->trust_any_certificate;
    }
    return self;
}

- (instancetype) initWithCoder: (NSCoder *)coder
{
    self = [super init];
    if (self) {
        _protocol = (AGDnsOutboundProxyProtocol)[coder decodeIntForKey:@"_protocol"];
        _address = [coder decodeObjectOfClass:NSString.class forKey:@"_address"];
        _port = [coder decodeInt64ForKey:@"_port"];
        _bootstrap = [coder decodeObjectOfClasses:[[NSSet alloc] initWithObjects:NSArray.class, NSString.class, nil] forKey:@"_bootstrap"];
        _authInfo = [coder decodeObjectOfClass:AGDnsOutboundProxyAuthInfo.class forKey:@"_authInfo"];
        _trustAnyCertificate = [coder decodeBoolForKey:@"_trustAnyCertificate"];
    }
    return self;
}

- (void) encodeWithCoder: (NSCoder *)coder
{
    [coder encodeInt:self.protocol forKey:@"_protocol"];
    [coder encodeObject:self.address forKey:@"_address"];
    [coder encodeInt64:self.port forKey:@"_port"];
    [coder encodeObject:self.bootstrap forKey:@"_bootstrap"];
    [coder encodeObject:self.authInfo forKey:@"_authInfo"];
    [coder encodeBool:self.trustAnyCertificate forKey:@"_trustAnyCertificate"];
}

- (NSString*)description {
    return [NSString stringWithFormat:
            @"[(%p)AGOutboundProxySettings: protocol=%ld, address=%@, port=%ld, bootstrap=(%@), authInfo=%@, trustAnyCertificate=%@]",
            self, _protocol, _address, _port, [_bootstrap componentsJoinedByString:@", "], _authInfo, _trustAnyCertificate ? @"YES" : @"NO"];
}

@end

@implementation AGDnsFilterParams

+ (BOOL)supportsSecureCoding {
    return YES;
}

- (instancetype)initWithCoder:(NSCoder *)coder {
    self = [super init];
    if (self) {
        _id = [coder decodeInt64ForKey:@"_id"];
        _data = [coder decodeObjectOfClass:NSString.class forKey:@"_data"];
        _inMemory = [coder decodeBoolForKey:@"_inMemory"];
    }

    return self;
}

- (void)encodeWithCoder:(NSCoder *)coder {
    [coder encodeInt64:self.id forKey:@"_id"];
    [coder encodeObject:self.data forKey:@"_data"];
    [coder encodeBool:self.inMemory forKey:@"_inMemory"];
}

- (NSString*)description {
    return [NSString stringWithFormat:@"[(%p)AGDnsFilterParams: id=%ld]", self, _id];
}

@end

#if TARGET_OS_IPHONE
@implementation AGDnsQosSettings

- (instancetype)initWithQosClass:(qos_class_t)qosClass
                relativePriority:(int)relativePriority
{
    self = [super init];
    if (self) {
        _qosClass = qosClass;

        if (relativePriority < QOS_MIN_RELATIVE_PRIORITY) {
            _relativePriority = QOS_MIN_RELATIVE_PRIORITY;
        } else {
            _relativePriority = relativePriority;
        }
    }
    return self;
}

- (instancetype)init {
    return [self initWithQosClass:QOS_CLASS_DEFAULT relativePriority:0];
}

- (instancetype)initWithNative:(const DnsQosSettings *)settings
{
    return [self initWithQosClass:settings->qos_class relativePriority:settings->relative_priority];
}

+ (BOOL)supportsSecureCoding {
    return YES;
}

- (void)encodeWithCoder:(NSCoder *)coder {
    [coder encodeInteger:_qosClass forKey:@"qosClass"];
    [coder encodeInteger:_relativePriority forKey:@"relativePriority"];
}

- (instancetype)initWithCoder:(NSCoder *)coder {
    auto qosClass = (qos_class_t)[coder decodeIntegerForKey:@"qosClass"];
    int relPrio = (int)[coder decodeIntegerForKey:@"relativePriority"];
    return [self initWithQosClass:qosClass relativePriority:relPrio];
}

- (NSString*)description {
    return [NSString stringWithFormat:
            @"[(%p)AGQosSettings: qosClass=%u, relativePriority=%d]",
            self, _qosClass, _relativePriority];
}

@end
#endif // TARGET_OS_IPHONE

@implementation AGDnsProxyConfig

+ (BOOL)supportsSecureCoding {
    return YES;
}

- (instancetype) initWithNative: (const DnsProxySettings *) settings
{
    self = [super init];
    NSMutableArray<AGDnsUpstream *> *upstreams =
        [[NSMutableArray alloc] initWithCapacity: settings->upstreams.size()];
    for (const UpstreamOptions &us : settings->upstreams) {
        [upstreams addObject: [[AGDnsUpstream alloc] initWithNative: &us]];
    }
    _upstreams = upstreams;
    NSMutableArray<AGDnsUpstream *> *fallbacks =
            [[NSMutableArray alloc] initWithCapacity: settings->fallbacks.size()];
    for (const UpstreamOptions &us : settings->fallbacks) {
        [fallbacks addObject: [[AGDnsUpstream alloc] initWithNative: &us]];
    }
    _fallbacks = fallbacks;
    NSMutableArray<NSString *> *fallbackDomains =
            [[NSMutableArray alloc] initWithCapacity: settings->fallback_domains.size()];
    for (auto &domain : settings->fallback_domains) {
        [fallbackDomains addObject: convert_string(domain)];
    }
    _fallbackDomains = fallbackDomains;
    _filters = nil;
#if TARGET_OS_IPHONE
    _filtersMemoryLimitBytes = FILTER_PARAMS_MEM_LIMIT_BYTES;
#endif // TARGET_OS_IPHONE
    _blockedResponseTtlSecs = settings->blocked_response_ttl_secs;
    if (settings->dns64.has_value()) {
        _dns64Settings = [[AGDns64Settings alloc] initWithNative: &settings->dns64.value()];
    }
    NSMutableArray<AGDnsListenerSettings *> *listeners =
            [[NSMutableArray alloc] initWithCapacity: settings->listeners.size()];
    for (const ListenerSettings &ls : settings->listeners) {
        [listeners addObject: [[AGDnsListenerSettings alloc] initWithNative: &ls]];
    }
    _listeners = listeners;
    if (settings->outbound_proxy.has_value()) {
        _outboundProxy = [[AGDnsOutboundProxySettings alloc] initWithNative: &settings->outbound_proxy.value()];
    }
    _ipv6Available = settings->ipv6_available;
    _blockIpv6 = settings->block_ipv6;
    _adblockRulesBlockingMode = (AGDnsBlockingMode) settings->adblock_rules_blocking_mode;
    _hostsRulesBlockingMode = (AGDnsBlockingMode) settings->hosts_rules_blocking_mode;
    _customBlockingIpv4 = convert_string(settings->custom_blocking_ipv4);
    _customBlockingIpv6 = convert_string(settings->custom_blocking_ipv6);
    _dnsCacheSize = settings->dns_cache_size;
    _upstreamTimeoutMs = settings->upstream_timeout.count();
    _optimisticCache = settings->optimistic_cache;
    _enableDNSSECOK = settings->enable_dnssec_ok;
    _enableRetransmissionHandling = settings->enable_retransmission_handling;
    _enableRouteResolver = settings->enable_route_resolver;
    _blockEch = settings->block_ech;
    _enableParallelUpstreamQueries = settings->enable_parallel_upstream_queries;
    _enableFallbackOnUpstreamsFailure = settings->enable_fallback_on_upstreams_failure;
    _enableServfailOnUpstreamsFailure = settings->enable_servfail_on_upstreams_failure;
    _enableHttp3 = settings->enable_http3;
#if TARGET_OS_IPHONE
    _qosSettings = [[AGDnsQosSettings alloc] initWithNative: &settings->qos_settings];
#endif // TARGET_OS_IPHONE
    return self;
}

- (instancetype)initWithCoder:(NSCoder *)coder {
    self = [super init];
    if (self) {
        _upstreams = [coder decodeObjectOfClasses:[[NSSet alloc] initWithObjects:NSArray.class, AGDnsUpstream.class, nil] forKey:@"_upstreams"];
        _fallbacks = [coder decodeObjectOfClasses:[[NSSet alloc] initWithObjects:NSArray.class, AGDnsUpstream.class, nil] forKey:@"_fallbacks"];
        _fallbackDomains = [coder decodeObjectOfClasses:[[NSSet alloc] initWithObjects:NSArray.class, NSString.class, nil] forKey:@"_fallbackDomains"];
        _detectSearchDomains = [coder decodeBoolForKey:@"_detectSearchDomains"];
        _filters = [coder decodeObjectOfClasses:[[NSSet alloc] initWithObjects:NSArray.class, AGDnsFilterParams.class, nil] forKey:@"_filters"];
#if TARGET_OS_IPHONE
        _filtersMemoryLimitBytes = [coder decodeInt64ForKey:@"_filtersMemoryLimitBytes"];
#endif // TARGET_OS_IPHONE
        _blockedResponseTtlSecs = [coder decodeInt64ForKey:@"_blockedResponseTtlSecs"];
        _dns64Settings = [coder decodeObjectOfClass:AGDns64Settings.class forKey:@"_dns64Settings"];
        _listeners = [coder decodeObjectOfClasses:[[NSSet alloc] initWithObjects:NSArray.class, AGDnsListenerSettings.class, nil] forKey:@"_listeners"];
        _outboundProxy = [coder decodeObjectOfClass:AGDnsOutboundProxySettings.class forKey:@"_outboundProxy"];
        _ipv6Available = [coder decodeBoolForKey:@"_ipv6Available"];
        _blockIpv6 = [coder decodeBoolForKey:@"_blockIpv6"];
        _adblockRulesBlockingMode = (AGDnsBlockingMode) [coder decodeIntForKey:@"_adblockRulesBlockingMode"];
        _hostsRulesBlockingMode = (AGDnsBlockingMode) [coder decodeIntForKey:@"_hostsRulesBlockingMode"];
        _customBlockingIpv4 = [coder decodeObjectOfClass:NSString.class forKey:@"_customBlockingIpv4"];
        _customBlockingIpv6 = [coder decodeObjectOfClass:NSString.class forKey:@"_customBlockingIpv6"];
        _dnsCacheSize = [coder decodeInt64ForKey:@"_dnsCacheSize"];
        _upstreamTimeoutMs = [coder decodeInt64ForKey:@"_upstreamTimeoutMs"];
        _optimisticCache = [coder decodeBoolForKey:@"_optimisticCache"];
        _enableDNSSECOK = [coder decodeBoolForKey:@"_enableDNSSECOK"];
        _enableRetransmissionHandling = [coder decodeBoolForKey:@"_enableRetransmissionHandling"];
        _enableRouteResolver = [coder decodeBoolForKey:@"_enableRouteResolver"];
        _blockEch = [coder decodeBoolForKey:@"_blockEch"];
        _enableParallelUpstreamQueries = [coder decodeBoolForKey:@"_enableParallelUpstreamQueries"];
        _enableFallbackOnUpstreamsFailure = [coder decodeBoolForKey:@"_enableFallbackOnUpstreamsFailure"];
        _enableServfailOnUpstreamsFailure = [coder decodeBoolForKey:@"_enableServfailOnUpstreamsFailure"];
        _enableHttp3 = [coder decodeBoolForKey:@"_enableHttp3"];
        _helperPath = [coder decodeObjectOfClass:NSString.class forKey:@"_helperPath"];
#if TARGET_OS_IPHONE
        _qosSettings = [coder decodeObjectOfClass:AGDnsQosSettings.class forKey:@"_qosSettings"];
        _callbacksQosSettings = [coder decodeObjectOfClass:AGDnsQosSettings.class forKey:@"_callbacksQosSettings"];
#endif // TARGET_OS_IPHONE
    }

    return self;
}

- (void)encodeWithCoder:(NSCoder *)coder {
    [coder encodeObject:self.upstreams forKey:@"_upstreams"];
    [coder encodeObject:self.fallbacks forKey:@"_fallbacks"];
    [coder encodeObject:self.fallbackDomains forKey:@"_fallbackDomains"];
    [coder encodeBool:self.detectSearchDomains forKey:@"_detectSearchDomains"];
    [coder encodeObject:self.filters forKey:@"_filters"];
#if TARGET_OS_IPHONE
    [coder encodeInt64:self.filtersMemoryLimitBytes forKey:@"_filtersMemoryLimitBytes"];
#endif // TARGET_OS_IPHONE
    [coder encodeInt64:self.blockedResponseTtlSecs forKey:@"_blockedResponseTtlSecs"];
    [coder encodeObject:self.dns64Settings forKey:@"_dns64Settings"];
    [coder encodeObject:self.listeners forKey:@"_listeners"];
    [coder encodeObject:self.outboundProxy forKey:@"_outboundProxy"];
    [coder encodeBool:self.ipv6Available forKey:@"_ipv6Available"];
    [coder encodeBool:self.blockIpv6 forKey:@"_blockIpv6"];
    [coder encodeInt:self.adblockRulesBlockingMode forKey:@"_adblockRulesBlockingMode"];
    [coder encodeInt:self.hostsRulesBlockingMode forKey:@"_hostsRulesBlockingMode"];
    [coder encodeObject:self.customBlockingIpv4 forKey:@"_customBlockingIpv4"];
    [coder encodeObject:self.customBlockingIpv6 forKey:@"_customBlockingIpv6"];
    [coder encodeInt64:self.dnsCacheSize forKey:@"_dnsCacheSize"];
    [coder encodeInt64:self.upstreamTimeoutMs forKey:@"_upstreamTimeoutMs"];
    [coder encodeBool:self.optimisticCache forKey:@"_optimisticCache"];
    [coder encodeBool:self.enableDNSSECOK forKey:@"_enableDNSSECOK"];
    [coder encodeBool:self.enableRetransmissionHandling forKey:@"_enableRetransmissionHandling"];
    [coder encodeBool:self.enableRouteResolver forKey:@"_enableRouteResolver"];
    [coder encodeBool:self.blockEch forKey:@"_blockEch"];
    [coder encodeBool:self.enableParallelUpstreamQueries forKey:@"_enableParallelUpstreamQueries"];
    [coder encodeBool:self.enableFallbackOnUpstreamsFailure forKey:@"_enableFallbackOnUpstreamsFailure"];
    [coder encodeBool:self.enableServfailOnUpstreamsFailure forKey:@"_enableServfailOnUpstreamsFailure"];
    [coder encodeBool:self.enableHttp3 forKey:@"_enableHttp3"];
    [coder encodeObject:self.helperPath forKey:@"_helperPath"];
#if TARGET_OS_IPHONE
    [coder encodeObject:self.qosSettings forKey:@"_qosSettings"];
    [coder encodeObject:self.callbacksQosSettings forKey:@"_callbacksQosSettings"];
#endif // TARGET_OS_IPHONE
}

- (NSString *)description {
    NSMutableString *description = [NSMutableString stringWithFormat:@"<%@: ", NSStringFromClass([self class])];
    [description appendFormat:@"self.upstreams=%@", self.upstreams];
    [description appendFormat:@", self.fallbacks=%@", self.fallbacks];
    [description appendFormat:@", self.fallbackDomains=%@", self.fallbackDomains];
    [description appendFormat:@", self.detectSearchDomains=%d", self.detectSearchDomains];
    [description appendFormat:@", self.filters=%@", self.filters];
    [description appendFormat:@", self.blockedResponseTtlSecs=%li", self.blockedResponseTtlSecs];
    [description appendFormat:@", self.dns64Settings=%@", self.dns64Settings];
    [description appendFormat:@", self.listeners=%@", self.listeners];
    [description appendFormat:@", self.outboundProxy=%@", self.outboundProxy];
    [description appendFormat:@", self.ipv6Available=%d", self.ipv6Available];
    [description appendFormat:@", self.blockIpv6=%d", self.blockIpv6];
    [description appendFormat:@", self.adblockRulesBlockingMode=%ld", (long) self.adblockRulesBlockingMode];
    [description appendFormat:@", self.hostsRulesBlockingMode=%ld", (long) self.hostsRulesBlockingMode];
    [description appendFormat:@", self.customBlockingIpv4=%@", self.customBlockingIpv4];
    [description appendFormat:@", self.customBlockingIpv6=%@", self.customBlockingIpv6];
    [description appendFormat:@", self.dnsCacheSize=%lu", self.dnsCacheSize];
    [description appendFormat:@", self.upstreamTimeoutMs=%lu", self.upstreamTimeoutMs];
    [description appendFormat:@", self.optimisticCache=%d", self.optimisticCache];
    [description appendFormat:@", self.enableDNSSECOK=%d", self.enableDNSSECOK];
    [description appendFormat:@", self.enableRetransmissionHandling=%d", self.enableRetransmissionHandling];
    [description appendFormat:@", self.enableRouteResolver=%d", self.enableRouteResolver];
    [description appendFormat:@", self.blockEch=%d", self.blockEch];
    [description appendFormat:@", self.enableParallelUpstreamQueries=%d", self.enableParallelUpstreamQueries];
    [description appendFormat:@", self.enableFallbackOnUpstreamsFailure=%d", self.enableFallbackOnUpstreamsFailure];
    [description appendFormat:@", self.enableServfailOnUpstreamsFailure=%d", self.enableServfailOnUpstreamsFailure];
    [description appendFormat:@", self.enableHttp3=%d", self.enableHttp3];
    [description appendFormat:@", self.helperPath=%@", self.helperPath];
#if TARGET_OS_IPHONE
    [description appendFormat:@", self.qosSettings=%@", self.qosSettings];
    [description appendFormat:@", self.callbacksQosSettings=%@", self.callbacksQosSettings];
#endif // TARGET_OS_IPHONE
    [description appendString:@">"];
    return description;
}

+ (instancetype) getDefault
{
    const DnsProxySettings &defaultSettings = DnsProxySettings::get_default();
    return [[AGDnsProxyConfig alloc] initWithNative: &defaultSettings];
}
@end

@implementation AGDnsRequestProcessedEvent

+ (BOOL)supportsSecureCoding {
    return YES;
}

- (instancetype) init: (const DnsRequestProcessedEvent &)event
{
    _domain = convert_string(event.domain);
    _type = convert_string(event.type);
    _startTime = event.start_time;
    _elapsed = event.elapsed;
    _status = convert_string(event.status);
    _answer = convert_string(event.answer);
    _originalAnswer = convert_string(event.original_answer);
    _upstreamId = event.upstream_id ? [NSNumber numberWithInt:*event.upstream_id] : nil;
    _bytesSent = event.bytes_sent;
    _bytesReceived = event.bytes_received;

    NSMutableArray<NSString *> *rules =
        [[NSMutableArray alloc] initWithCapacity: event.rules.size()];
    NSMutableArray<NSNumber *> *filterListIds =
        [[NSMutableArray alloc] initWithCapacity: event.rules.size()];
    for (size_t i = 0; i < event.rules.size(); ++i) {
        [rules addObject: convert_string(event.rules[i])];
        [filterListIds addObject: [NSNumber numberWithInt: event.filter_list_ids[i]]];
    }
    _rules = rules;
    _filterListIds = filterListIds;

    _whitelist = event.whitelist;
    _error = convert_string(event.error);

    _cacheHit = event.cache_hit;

    _dnssec = event.dnssec;

    return self;
}

- (ag::dns::DnsRequestProcessedEvent)nativeEvent {
    ag::dns::DnsRequestProcessedEvent event;
    event.original_answer = convert_string(_originalAnswer);
    event.answer = convert_string(_answer);
    event.bytes_received = _bytesReceived;
    event.bytes_sent = _bytesSent;
    event.cache_hit = _cacheHit;
    event.dnssec = _dnssec;
    event.status = convert_string(_status);
    event.domain = convert_string(_domain);
    event.elapsed = _elapsed;
    event.error = convert_string(_error);
    for (NSNumber *id in _filterListIds) {
        event.filter_list_ids.emplace_back(id.intValue);
    }
    for (NSString *rule in _rules) {
        event.rules.emplace_back(convert_string(rule));
    }
    event.start_time = _startTime;
    event.type = convert_string(_type);
    if (_upstreamId) {
        event.upstream_id = _upstreamId.intValue;
    }
    event.whitelist = _whitelist;
    return event;
}

- (instancetype)initWithCoder:(NSCoder *)coder {
    self = [super init];
    if (self) {
        _domain = [coder decodeObjectOfClass:NSString.class forKey:@"_domain"];
        _type = [coder decodeObjectOfClass:NSString.class forKey:@"_type"];
        _startTime = [coder decodeInt64ForKey:@"_startTime"];
        _elapsed = [coder decodeInt64ForKey:@"_elapsed"];
        _status = [coder decodeObjectOfClass:NSString.class forKey:@"_status"];
        _answer = [coder decodeObjectOfClass:NSString.class forKey:@"_answer"];
        _originalAnswer = [coder decodeObjectOfClass:NSString.class forKey:@"_originalAnswer"];
        _upstreamId = [coder decodeObjectOfClass:NSNumber.class forKey:@"_upstreamId"];
        _bytesSent = [coder decodeInt64ForKey:@"_bytesSent"];
        _bytesReceived = [coder decodeInt64ForKey:@"_bytesReceived"];
        _rules = [coder decodeObjectOfClasses:[[NSSet alloc] initWithObjects:NSArray.class, NSString.class, nil] forKey:@"_rules"];
        _filterListIds = [coder decodeObjectOfClasses:[[NSSet alloc] initWithObjects:NSArray.class, NSNumber.class, nil] forKey:@"_filterListIds"];
        _whitelist = [coder decodeBoolForKey:@"_whitelist"];
        _error = [coder decodeObjectOfClass:NSString.class forKey:@"_error"];
        _cacheHit = [coder decodeBoolForKey:@"_cacheHit"];
        _dnssec = [coder decodeBoolForKey:@"_dnssec"];
    }

    return self;
}

- (void)encodeWithCoder:(NSCoder *)coder {
    [coder encodeObject:self.domain forKey:@"_domain"];
    [coder encodeObject:self.type forKey:@"_type"];
    [coder encodeInt64:self.startTime forKey:@"_startTime"];
    [coder encodeInt64:self.elapsed forKey:@"_elapsed"];
    [coder encodeObject:self.status forKey:@"_status"];
    [coder encodeObject:self.answer forKey:@"_answer"];
    [coder encodeObject:self.originalAnswer forKey:@"_originalAnswer"];
    [coder encodeObject:self.upstreamId forKey:@"_upstreamId"];
    [coder encodeInt64:self.bytesSent forKey:@"_bytesSent"];
    [coder encodeInt64:self.bytesReceived forKey:@"_bytesReceived"];
    [coder encodeObject:self.rules forKey:@"_rules"];
    [coder encodeObject:self.filterListIds forKey:@"_filterListIds"];
    [coder encodeBool:self.whitelist forKey:@"_whitelist"];
    [coder encodeObject:self.error forKey:@"_error"];
    [coder encodeBool:self.cacheHit forKey:@"_cacheHit"];
    [coder encodeBool:self.dnssec forKey:@"_dnssec"];
}

- (NSString*)description {
    return [NSString stringWithFormat:
            @"[(%p)AGDnsRequestProcessedEvent: domain=%@, "
            "type=%@, "
            "status=%@, "
            "answer=%@, "
            "originalAnswer=%@, "
            "upstreamId=%@, "
            "filterListIds=%@, "
            "whitelist=%@, "
            "error=%@, "
            "cacheHit=%@, "
            "dnssec=%@]",
            self, _domain, _type, _status, _answer, _originalAnswer, _upstreamId, _filterListIds,
            _whitelist ? @"YES" : @"NO", _error, _cacheHit ? @"YES" : @"NO", _dnssec ? @"YES" : @"NO"];
}

@end

@implementation AGDnsProxyEvents
@end

@implementation AGDnsProxy {
    DnsProxy proxy;
    std::optional<Logger> log;
    AGDnsProxyEvents *events;
    dispatch_queue_t queue;
    BOOL initialized;
}

- (void)dealloc
{
    if (initialized) {
        @throw [NSException exceptionWithName:@"Illegal state"
                                       reason:@"AGDnsProxy was not stopped before dealloc"
                                     userInfo:nil];
    }
}

- (void)stop {
    if (initialized) {
        auto block = ^{
            self->proxy.deinit();
            initialized = NO;
        };
        if (dispatch_get_specific(IS_DNS_QUEUE_KEY) == (void *) 0x1) {
            block();
        } else {
            dispatch_sync(queue, block);
        }
    }
}

static SecCertificateRef convertCertificate(const std::vector<uint8_t> &cert) {
    NSData *data = [NSData dataWithBytesNoCopy: (void *)cert.data() length: cert.size() freeWhenDone: NO];
    CFDataRef certRef = (__bridge CFDataRef)data;
    return SecCertificateCreateWithData(NULL, (CFDataRef)certRef);
}

static std::string getTrustCreationErrorStr(OSStatus status) {
#if !TARGET_OS_IPHONE || (IOS_VERSION_MAJOR >= 11 && IOS_VERSION_MINOR >= 3)
    auto *err = (__bridge_transfer NSString *) SecCopyErrorMessageString(status, NULL);
    return [err UTF8String];
#else
    return AG_FMT("Failed to create trust object from chain: {}", status);
#endif
}

template <typename T>
using AGUniqueCFRef = UniquePtr<std::remove_pointer_t<T>, &CFRelease>;

+ (std::optional<std::string>) verifyCertificate: (CertificateVerificationEvent *) event log: (Logger &) log
{
    tracelog(log, "[Verification] App callback");

    NSMutableArray *trustArray = [[NSMutableArray alloc] initWithCapacity: event->chain.size() + 1];

    SecCertificateRef cert = convertCertificate(event->certificate);
    if (!cert) {
        dbglog(log, "[Verification] Failed to create certificate object");
        return "Failed to create certificate object";
    }
    [trustArray addObject:(__bridge_transfer id) cert];

    for (const auto &chainCert : event->chain) {
        cert = convertCertificate(chainCert);
        if (!cert) {
            dbglog(log, "[Verification] Failed to create certificate object");
            return "Failed to create certificate object";
        }
        [trustArray addObject:(__bridge_transfer id) cert];
    }

    AGUniqueCFRef<SecPolicyRef> policy{SecPolicyCreateBasicX509()};
    SecTrustRef trust;
    OSStatus status = SecTrustCreateWithCertificates((__bridge CFTypeRef) trustArray, policy.get(), &trust);

    if (status != errSecSuccess) {
        std::string err = getTrustCreationErrorStr(status);
        dbglog(log, "[Verification] Failed to create trust object from chain: {}", err);
        return err;
    }

    AGUniqueCFRef<SecTrustRef> trustRef{trust};

    SecTrustSetAnchorCertificates(trust, NULL);
    SecTrustSetAnchorCertificatesOnly(trust, NO);
    SecTrustResultType trustResult;
    SecTrustEvaluate(trust, &trustResult);

    // https://developer.apple.com/documentation/security/sectrustresulttype/ksectrustresultunspecified?language=objc
    // This value indicates that evaluation reached an (implicitly trusted) anchor certificate without
    // any evaluation failures, but never encountered any explicitly stated user-trust preference.
    if (trustResult == kSecTrustResultUnspecified || trustResult == kSecTrustResultProceed) {
        dbglog(log, "[Verification] Succeeded");
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
        errStr = AG_FMT("Unknown error code: {}", magic_enum::enum_name(trustResult));
        break;
    }

    dbglog(log, "[Verification] Failed to verify: {}", errStr);
    return errStr;
}

static UpstreamOptions convert_upstream(AGDnsUpstream *upstream) {
    std::vector<std::string> bootstrap;
    std::vector<std::string> fingerprints;
    if (upstream.bootstrap != nil) {
        bootstrap.reserve([upstream.bootstrap count]);
        for (NSString *server in upstream.bootstrap) {
            bootstrap.emplace_back([server UTF8String]);
        }
    }
    IpAddress addr;
    if (upstream.serverIp != nil && [upstream.serverIp length] == 4) {
        addr.emplace<Uint8Array<4>>();
        std::memcpy(std::get<Uint8Array<4>>(addr).data(),
                    [upstream.serverIp bytes], [upstream.serverIp length]);
    } else if (upstream.serverIp != nil && [upstream.serverIp length] == 16) {
        addr.emplace<Uint8Array<16>>();
        std::memcpy(std::get<Uint8Array<16>>(addr).data(),
                    [upstream.serverIp bytes], [upstream.serverIp length]);
    }
    IfIdVariant iface;
    if (upstream.outboundInterfaceName != nil) {
        iface.emplace<std::string>(upstream.outboundInterfaceName.UTF8String);
    }
    if (upstream.fingerprints != nil) {
        fingerprints.reserve([upstream.fingerprints count]);
        for (NSString *fp in upstream.fingerprints) {
            fingerprints.emplace_back([fp UTF8String]);
        }
    }
    return UpstreamOptions{
            .address = [upstream.address UTF8String],
            .bootstrap = std::move(bootstrap),
            .resolved_server_ip = std::move(addr),
            .id = (int32_t) upstream.id,
            .outbound_interface = std::move(iface),
            .fingerprints = std::move(fingerprints)};
}

static std::vector<UpstreamOptions> convert_upstreams(NSArray<AGDnsUpstream *> *upstreams) {
    std::vector<UpstreamOptions> converted;
    if (upstreams != nil) {
        converted.reserve([upstreams count]);
        for (AGDnsUpstream *upstream in upstreams) {
            converted.emplace_back(convert_upstream(upstream));
        }
    }
    return converted;
}

static void append_search_domains(std::vector<std::string> &fallback_domains) {
    struct __res_state resState = {0};
    res_ninit(&resState);
    for (int i = 0; i < MAXDNSRCH; ++i) {
        if (resState.dnsrch[i]) {
            std::string_view search_domain = resState.dnsrch[i];
            if (!search_domain.empty() && search_domain.back() == '.') {
                search_domain.remove_suffix(1);
            }
            if (!search_domain.empty() && search_domain.front() == '.') {
                search_domain.remove_prefix(1);
            }
            if (!search_domain.empty()) {
                fallback_domains.emplace_back(AG_FMT("*.{}", search_domain));
            }
        }
    }
    res_nclose(&resState);
}

#if !TARGET_OS_IPHONE

typedef struct {
    int ourFd;
    int theirFd;
} fd_pair_t;

static fd_pair_t makeFdPairForTask() {
    int pair[2] = {-1, -1};
    int r = socketpair(AF_UNIX, SOCK_STREAM, 0, pair);
    if (r == -1) {
        goto error;
    }
    r = evutil_make_socket_closeonexec(pair[0]);
    if (r == -1) {
        goto error;
    }
    r = evutil_make_socket_closeonexec(pair[1]);
    if (r == -1) {
        goto error;
    }
    return (fd_pair_t) {pair[0], pair[1]};
    error:
    close(pair[0]);
    close(pair[1]);
    return (fd_pair_t) {-1, -1};
}

static NSString *getProtoString(AGDnsListenerProtocol proto) {
    switch (proto) {
        case AGLP_UDP:
            return @"udp";
            break;
        case AGLP_TCP:
            return @"tcp";
            break;
    }
    return nil;
}

static int receiveFd(int ourFd, NSError **error) {
    char buf[1]{};
    char cmsgspace[CMSG_SPACE(sizeof(int))]{};
    iovec vec{
            .iov_base = buf,
            .iov_len = sizeof(buf)};
    msghdr msg{
            .msg_iov = &vec,
            .msg_iovlen = 1,
            .msg_control = &cmsgspace,
            .msg_controllen = CMSG_LEN(sizeof(int))};

    int r = recvmsg(ourFd, &msg, 0);
    if (r < 0) {
        *error = [NSError errorWithDomain:AGDnsProxyErrorDomain
                                     code:AGDPE_PROXY_INIT_ERROR
                                 userInfo:@{NSLocalizedDescriptionKey:
                                            [NSString stringWithFormat:@"Failed to receive fd: %s", strerror(errno)]}];
        return -1;
    }

    for (cmsghdr *cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
        if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS) {
            return *(int *) CMSG_DATA(cmsg);
        }
    }

    return -1;
}

// Bind an fd using adguard-tun-helper
static int bindFd(NSString *helperPath, NSString *address, NSNumber *port, AGDnsListenerProtocol proto, NSError **error) {
    NSString *protoString = getProtoString(proto);
    if (protoString == nil) {
        *error = [NSError errorWithDomain:AGDnsProxyErrorDomain
                                     code:AGDPE_PROXY_INIT_ERROR
                                 userInfo:@{NSLocalizedDescriptionKey: @"Bad listener protocol"}];
        return -1;
    }

    fd_pair_t fdPair = makeFdPairForTask();
    if (fdPair.ourFd == -1 || fdPair.theirFd == -1) {
        *error = [NSError errorWithDomain:AGDnsProxyErrorDomain
                                     code:AGDPE_PROXY_INIT_ERROR
                                 userInfo:@{NSLocalizedDescriptionKey: @"Failed to make an fd pair"}];
        return -1;
    }
    evutil_make_socket_nonblocking(fdPair.ourFd);

    // Setup task
    auto *task = [[NSTask alloc] init];
    task.launchPath = helperPath;
    task.arguments = @[@"--bind", address, port.stringValue, protoString];
    NSFileHandle *nullDevice = [NSFileHandle fileHandleWithNullDevice];
    task.standardInput = nullDevice;
    task.standardOutput = [[NSFileHandle alloc] initWithFileDescriptor:fdPair.theirFd closeOnDealloc:NO];
    task.standardError = nullDevice;

    // Start task
    NSError *taskError;
    dispatch_group_t taskGroup = [task launchWithGroupAndReturnError:&taskError];
    close(fdPair.theirFd);
    if (!taskGroup) {
        NSString *description = taskError.localizedDescription;
        *error = [NSError errorWithDomain:AGDnsProxyErrorDomain
                                     code:AGDPE_PROXY_INIT_ERROR
                                 userInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat:@"Error starting tun helper: %@", description]}];
        close(fdPair.ourFd);
        return -1;
    }

    // Read fd from helper
    __block int receivedFd = -1;
    __block NSError *receiveError = nil;
    dispatch_source_t read = dispatch_source_create(DISPATCH_SOURCE_TYPE_READ, fdPair.ourFd, 0, 0);
    dispatch_source_set_event_handler(read, ^{
        receivedFd = receiveFd(fdPair.ourFd, &receiveError);
        dispatch_source_cancel(read);
    });
    dispatch_source_set_cancel_handler(read, ^{
        close(fdPair.ourFd);
    });
    dispatch_resume(read);

    // Close and wait for exit or timeout
    if (0 != dispatch_group_wait(taskGroup, dispatch_time(DISPATCH_TIME_NOW, BINDFD_WAIT_MS * NSEC_PER_MSEC))) {
        NSString *description = [NSString stringWithFormat: @"Failed to receive fd: helper timed out"];
        *error = [NSError errorWithDomain:AGDnsProxyErrorDomain
                                     code:AGDPE_PROXY_INIT_HELPER_ERROR
                                 userInfo:@{NSLocalizedDescriptionKey: description}];
        [task interrupt];
        dispatch_source_cancel(read);
        return -1;
    }

    switch (task.terminationStatus) {
        case 0:
            if (receivedFd != -1) {
                return receivedFd;
            }
            *error = receiveError
                     ? receiveError
                     : [NSError errorWithDomain:AGDnsProxyErrorDomain
                                           code:AGDPE_PROXY_INIT_ERROR
                                       userInfo:@{NSLocalizedDescriptionKey: @"Failed to receive fd: control message not found"}];
            break;
        case ERR_BIND_IN_USE:
            *error = [NSError errorWithDomain:AGDnsProxyErrorDomain
                                         code:AGDPE_PROXY_INIT_HELPER_BIND_ERROR
                                     userInfo:@{NSLocalizedDescriptionKey: @"Failed to receive fd: can't bind"}];
            break;
        default:
            NSString *description = [NSString stringWithFormat: @"Failed to receive fd: helper return %d", task.terminationStatus];
            *error = [NSError errorWithDomain:AGDnsProxyErrorDomain
                                         code:AGDPE_PROXY_INIT_HELPER_ERROR
                                     userInfo:@{NSLocalizedDescriptionKey: description}];
            break;
    }

    return -1;
}

#endif // !TARGET_OS_IPHONE

static ProxySettingsOverrides convertProxySettingsOverrides(const AGDnsProxySettingsOverrides *x) {
    ProxySettingsOverrides ret = {};
    if (x != nil) {
        ret.block_ech = (x.blockEch == nil) ? std::nullopt : std::make_optional<bool>([x.blockEch boolValue]);
    }
    return ret;
}

- (instancetype) initWithConfig: (AGDnsProxyConfig *) config
                        handler: (AGDnsProxyEvents *) handler
                          error: (NSError **) error
{
    self = [super init];
    if (!self) {
        return nil;
    }
    self->initialized = NO;

    self->log = Logger{"AGDnsProxy"};

    infolog(*self->log, "Initializing dns proxy...");

    DnsProxySettings settings = DnsProxySettings::get_default();
    settings.upstreams = convert_upstreams(config.upstreams);
    settings.fallbacks = convert_upstreams(config.fallbacks);

    if (config.fallbackDomains) {
        for (NSString *domain in config.fallbackDomains) {
            settings.fallback_domains.emplace_back(domain.UTF8String);
        }
    }
    if (config.detectSearchDomains) {
        append_search_domains(settings.fallback_domains);
    }

    settings.blocked_response_ttl_secs = (uint32_t) config.blockedResponseTtlSecs;

    if (config.filters != nil) {
        settings.filter_params.filters.reserve([config.filters count]);
        for (AGDnsFilterParams *fp in config.filters) {
            dbglog(*self->log, "Filter id={} {}={}", fp.id, fp.inMemory ? "content" : "path",
                    fp.inMemory ? AG_FMT("{} bytes", fp.data.length) : fp.data.UTF8String);

            settings.filter_params.filters.emplace_back(
                DnsFilter::FilterParams{(int32_t) fp.id, fp.data.UTF8String, (bool) fp.inMemory});
        }
#if TARGET_OS_IPHONE
        settings.filter_params.mem_limit = config.filtersMemoryLimitBytes;
#endif // TARGET_OS_IPHONE
    }

    void *obj = (__bridge void *)self;

    dispatch_queue_attr_t attr = nil;
#if TARGET_OS_IPHONE
    attr = dispatch_queue_attr_make_with_qos_class(DISPATCH_QUEUE_SERIAL,
                                                   config.callbacksQosSettings.qosClass,
                                                   config.callbacksQosSettings.relativePriority);
#endif // TARGET_OS_IPHONE
    self->queue = dispatch_queue_create("com.adguard.dnslibs.AGDnsProxy.queue", attr);
    dispatch_queue_set_specific(self->queue, IS_DNS_QUEUE_KEY, (void *) 0x1, nullptr);
    self->events = handler;
    DnsProxyEvents native_events = {};
    if (handler != nil && handler.onRequestProcessed != nil) {
         native_events.on_request_processed =
            [obj] (const DnsRequestProcessedEvent &event) {
                auto *sself = (__bridge AGDnsProxy *)obj;
                @autoreleasepool {
                    auto *objCEvent = [[AGDnsRequestProcessedEvent alloc] init: event];
                    __weak AGDnsProxyEvents *weakObjCEvents = sself->events;
                    dispatch_async(sself->queue, ^{
                        __strong AGDnsProxyEvents *objCEvents = weakObjCEvents;
                        if (objCEvents) {
                            objCEvents.onRequestProcessed(objCEvent);
                        }
                    });
                }
            };
    }
    native_events.on_certificate_verification =
        [obj] (CertificateVerificationEvent event) {
            @autoreleasepool {
                AGDnsProxy *sself = (__bridge AGDnsProxy *)obj;
                return [AGDnsProxy verifyCertificate: &event log: *sself->log];
            }
        };

    if (config.dns64Settings != nil) {
        NSArray<AGDnsUpstream *> *dns64_upstreams = config.dns64Settings.upstreams;
        if (dns64_upstreams == nil) {
            dbglog(*self->log, "DNS64 upstreams list is nil");
        } else if ([dns64_upstreams count] == 0) {
            dbglog(*self->log, "DNS64 upstreams list is empty");
        } else {
            settings.dns64 = Dns64Settings{
                    .upstreams = convert_upstreams(dns64_upstreams),
                    .max_tries = config.dns64Settings.maxTries > 0
                                 ? static_cast<uint32_t>(config.dns64Settings.maxTries) : 0,
                    .wait_time = std::chrono::milliseconds(config.dns64Settings.waitTimeMs),
            };
        }
    }

    std::vector<std::shared_ptr<void>> closefds; // Close fds on return
    if (config.listeners != nil) {
        closefds.reserve(config.listeners.count);
        settings.listeners.clear();
        settings.listeners.reserve(config.listeners.count);
        dbglog(*self->log, "Creating listener fds if needed");
        for (AGDnsListenerSettings *listener in config.listeners) {
            int listenerFd = -1;
#if !TARGET_OS_IPHONE
            if (config.helperPath && listener.port > 0 && listener.port < 1024) {
                dbglog(*self->log, "Creating listener fd for proto={} address={} port={}",
                       (listener.proto == AGLP_TCP) ? "tcp" : "udp",
                       listener.address.UTF8String ? listener.address.UTF8String : "(null)",
                       listener.port);
                listenerFd = bindFd(config.helperPath, listener.address, @(listener.port), listener.proto, error);
                if (listenerFd == -1) {
                    NSString *description = [(NSError *) *error localizedDescription];
                    dbglog(*self->log, "Error creating listener fd: {}", description.UTF8String ? description.UTF8String : "(null)");
                    return nil;
                }
                closefds.emplace_back(nullptr, [listenerFd](void *p) {
                    close(listenerFd);
                }); // Close on return (listener does dup())
            }
#endif
            dbglog(*self->log, "Adding listener (fd={}) for proto={} address={} port={}",
                   listenerFd,
                   (listener.proto == AGLP_TCP) ? "tcp" : "udp",
                   listener.address.UTF8String ? listener.address.UTF8String : "(null)",
                   listener.port);
            settings.listeners.emplace_back((ListenerSettings) {
                .address = listener.address.UTF8String,
                .port = (uint16_t) listener.port,
                .protocol = (ag::utils::TransportProtocol) listener.proto,
                .persistent = (bool) listener.persistent,
                .idle_timeout = std::chrono::milliseconds(listener.idleTimeoutMs),
                .settings_overrides = convertProxySettingsOverrides(listener.settingsOverrides),
                .fd = listenerFd,
            });
        }
        dbglog(*self->log, "Finished creating listener fds if needed, {} pending to close", closefds.size());
    }

    settings.ipv6_available = config.ipv6Available;
    settings.block_ipv6 = config.blockIpv6;

    settings.adblock_rules_blocking_mode = (DnsProxyBlockingMode) config.adblockRulesBlockingMode;
    settings.hosts_rules_blocking_mode = (DnsProxyBlockingMode) config.hostsRulesBlockingMode;
    if (config.customBlockingIpv4 != nil) {
        settings.custom_blocking_ipv4 = [config.customBlockingIpv4 UTF8String];
    }
    if (config.customBlockingIpv6 != nil) {
        settings.custom_blocking_ipv6 = [config.customBlockingIpv6 UTF8String];
    }

    settings.dns_cache_size = config.dnsCacheSize;
    settings.optimistic_cache = config.optimisticCache;
    settings.enable_dnssec_ok = config.enableDNSSECOK;
    settings.enable_retransmission_handling = config.enableRetransmissionHandling;
    settings.enable_route_resolver = config.enableRouteResolver;
    settings.block_ech = config.blockEch;
    settings.enable_parallel_upstream_queries = config.enableParallelUpstreamQueries;
    settings.enable_fallback_on_upstreams_failure = config.enableFallbackOnUpstreamsFailure;
    settings.enable_servfail_on_upstreams_failure = config.enableServfailOnUpstreamsFailure;

#if TARGET_OS_IPHONE
    settings.qos_settings.qos_class = config.qosSettings.qosClass;
    settings.qos_settings.relative_priority = config.qosSettings.relativePriority;
#endif // TARGET_OS_IPHONE

    auto [ret, err_or_warn] = self->proxy.init(std::move(settings), std::move(native_events));
    if (!ret) {
        auto str = AG_FMT("Failed to initialize the DNS proxy: {}", err_or_warn->str());
        errlog(*self->log, "{}", str);
        if (error) {
            *error = [NSError errorWithDomain:AGDnsProxyErrorDomain
                                         code:(AGDnsProxyInitError)(err_or_warn->value())
                                     userInfo:@{NSLocalizedDescriptionKey : convert_string(str)}];
        }
        return nil;
    }
    if (error && err_or_warn) {
        auto str = AG_FMT("DNS proxy initialized with warnings:\n{}", err_or_warn->str());
        *error = [NSError errorWithDomain:AGDnsProxyErrorDomain
                                     code:(AGDnsProxyInitError)(err_or_warn->value())
                                 userInfo:@{NSLocalizedDescriptionKey : convert_string(str)}];
    }
    self->initialized = YES;

    infolog(*self->log, "Dns proxy initialized");

    return self;
}

static coro::Task<CFDataRef> handleIPv4Packet(AGDnsProxy *self, NSData *packet)
{
    auto *ip_header = (struct iphdr *) packet.bytes;
    // @todo: handle tcp packets also
    if (ip_header->ip_p != IPPROTO_UDP) {
        co_return nil;
    }

    NSInteger ip_header_length = ip_header->ip_hl * 4;
    auto *udp_header = (struct udphdr *) ((Byte *) packet.bytes + ip_header_length);
    NSInteger header_length = ip_header_length + sizeof(*udp_header);

    char srcv4_str[INET_ADDRSTRLEN], dstv4_str[INET_ADDRSTRLEN];
    dbglog(*self->log, "{}:{} -> {}:{}",
           inet_ntop(AF_INET, &ip_header->ip_src, srcv4_str, sizeof(srcv4_str)), ntohs(udp_header->uh_sport),
           inet_ntop(AF_INET, &ip_header->ip_dst, dstv4_str, sizeof(dstv4_str)), ntohs(udp_header->uh_dport));

    if (ntohs(udp_header->uh_dport) != DEFAULT_PLAIN_PORT) {
        dbglog(*self->log, "Dropping non-DNS packet");
        co_return nil;
    }

    Uint8View payload = {(uint8_t *) packet.bytes + header_length, packet.length - header_length};
    DnsMessageInfo info{
            .proto = ag::utils::TP_UDP,
            .peername = SocketAddress{{(uint8_t *) &ip_header->ip_src, sizeof(ip_header->ip_src)},
                                           ntohs(udp_header->uh_sport)}};
    std::vector<uint8_t> response = co_await self->proxy.handle_message(payload, &info);
    if (response.empty()) {
        co_return nil;
    }
    co_return create_response_packet(ip_header, udp_header, response);
}

static coro::Task<CFDataRef> handleIPv6Packet(AGDnsProxy *self, NSData *packet)
{
    auto *ip_header = (struct iphdr6 *) packet.bytes;
    // @todo: handle tcp packets also
    if (ip_header->ip6_nh != IPPROTO_UDP) {
        co_return nil;
    }

    NSInteger ip_header_length = sizeof(*ip_header);
    auto *udp_header = (struct udphdr *) ((Byte *) packet.bytes + ip_header_length);
    NSInteger header_length = ip_header_length + sizeof(*udp_header);

    char srcv6_str[INET6_ADDRSTRLEN], dstv6_str[INET6_ADDRSTRLEN];
    dbglog(*self->log, "[{}]:{} -> [{}]:{}",
           inet_ntop(AF_INET6, &ip_header->ip6_src, srcv6_str, sizeof(srcv6_str)), ntohs(udp_header->uh_sport),
           inet_ntop(AF_INET6, &ip_header->ip6_dst, dstv6_str, sizeof(dstv6_str)), ntohs(udp_header->uh_dport));

    if (ntohs(udp_header->uh_dport) != DEFAULT_PLAIN_PORT) {
        dbglog(*self->log, "Dropping non-DNS packet");
        co_return nil;
    }

    Uint8View payload = {(uint8_t *) packet.bytes + header_length, packet.length - header_length};
    DnsMessageInfo info{
            .proto = ag::utils::TP_UDP,
            .peername = SocketAddress{{(uint8_t *) &ip_header->ip6_src, sizeof(ip_header->ip6_src)},
                                           ntohs(udp_header->uh_sport)}};
    std::vector<uint8_t> response = co_await self->proxy.handle_message(payload, &info);
    if (response.empty()) {
        co_return nil;
    }
    co_return create_response_packet_v6(ip_header, udp_header, response);
}

- (void)handlePacket:(NSData *)packet completionHandler:(void(^)(NSData *)) completionHandler
{
    dispatch_async(queue, ^{
        if (!initialized) {
            completionHandler([NSData new]);
            return;
        }
        coro::run_detached([](AGDnsProxy *self, NSData *packet, void (^completionHandler)(NSData *)) -> coro::Task<void> {
            auto *ip_header = (const struct iphdr *)packet.bytes;
            CFDataRef reply = nullptr;
            if (ip_header->ip_v == 4) {
                reply = co_await handleIPv4Packet(self, packet);
            } else if (ip_header->ip_v == 6) {
                reply = co_await handleIPv6Packet(self, packet);
            } else {
                dbglog(*self->log, "Wrong IP version: {}", ip_header->ip_v);
            }

            @autoreleasepool {
                completionHandler((__bridge_transfer NSData *) reply);
            }
        }(self, packet, completionHandler));
    });
}

- (void)handleMessage:(NSData *)message
             withInfo:(AGDnsMessageInfo *)info
withCompletionHandler:(void (^)(NSData *))handler {
    dispatch_async(queue, ^{
        if (!initialized) {
            handler([NSData new]);
            return;
        }
        coro::run_detached([](AGDnsProxy *self, NSData *message, AGDnsMessageInfo *info,
                                   void (^handler)(NSData *)) -> coro::Task<void> {
            std::optional<DnsMessageInfo> cpp_info;
            if (info) {
                cpp_info.emplace();
                cpp_info->transparent = info.transparent;
            }
            auto result = co_await self->proxy.handle_message({(uint8_t *) message.bytes, (size_t) message.length},
                    opt_as_ptr(cpp_info));
            @autoreleasepool {
                handler([NSData dataWithBytes:result.data() length:result.size()]);
            }
        }(self, message, info, handler));
    });
}

+ (BOOL) isValidRule: (NSString *) str
{
    return DnsFilter::is_valid_rule([str UTF8String]);
}

+ (NSString *)libraryVersion {
    return convert_string(DnsProxy::version());
}

@end

@implementation AGDnsStamp

- (instancetype) initWithNative: (const ServerStamp *) stamp
{
    self = [super init];
    if (self) {
        _proto = (AGStampProtoType) stamp->proto;
        _serverAddr = convert_string(stamp->server_addr_str);
        _providerName = convert_string(stamp->provider_name);
        _path = convert_string(stamp->path);
        if (!stamp->server_pk.empty()) {
            _serverPublicKey = [NSData dataWithBytes: stamp->server_pk.data() length: stamp->server_pk.size()];
        }
        if (!stamp->hashes.empty()) {
            NSMutableArray *hs = [NSMutableArray arrayWithCapacity: stamp->hashes.size()];
            for (const std::vector<uint8_t> &h : stamp->hashes) {
                [hs addObject: [NSData dataWithBytes: h.data() length: h.size()]];
            }
            _hashes = hs;
        }
        if (stamp->props.has_value()) {
            _properties = @((unsigned long long)stamp->props.value());
        } else {
            _properties = nil;
        }
    }
    return self;
}

- (instancetype)initWithCoder:(NSCoder *)coder {
    self = [super init];
    if (self) {
        _proto = (AGStampProtoType) [coder decodeIntForKey:@"_proto"];
        _serverAddr = [coder decodeObjectOfClass:NSString.class forKey:@"_serverAddr"];
        _providerName = [coder decodeObjectOfClass:NSString.class forKey:@"_providerName"];
        _path = [coder decodeObjectOfClass:NSString.class forKey:@"_path"];
        _serverPublicKey = [coder decodeObjectOfClass:NSData.class forKey:@"_serverPublicKey"];
        _hashes = [coder decodeObjectOfClasses:[[NSSet alloc] initWithObjects:NSArray.class, NSData.class, nil] forKey:@"_hashes"];
        _properties = [coder decodeObjectOfClass:NSNumber.class forKey:@"_properties"];
    }

    return self;
}

- (void)encodeWithCoder:(NSCoder *)coder {
    [coder encodeInt:self.proto forKey:@"_proto"];
    [coder encodeObject:self.serverAddr forKey:@"_serverAddr"];
    [coder encodeObject:self.providerName forKey:@"_providerName"];
    [coder encodeObject:self.path forKey:@"_path"];
    [coder encodeObject:self.serverPublicKey forKey:@"_serverPublicKey"];
    [coder encodeObject:self.hashes forKey:@"_hashes"];
    [coder encodeObject:self.properties forKey:@"_properties"];
}

- (instancetype)initWithString:(NSString *)stampStr
                         error:(NSError **)error {
    auto stamp = ServerStamp::from_string(stampStr.UTF8String);
    if (!stamp.has_error()) {
        return [self initWithNative:&stamp.value()];
    }
    if (error) {
        *error = [NSError errorWithDomain:AGDnsProxyErrorDomain
                                     code:(int)(stamp.error()->value())
                                 userInfo:@{NSLocalizedDescriptionKey: convert_string(stamp.error()->str())}];
    }
    return nil;
}

+ (instancetype)stampWithString:(NSString *)stampStr
                          error:(NSError **)error {
    return [[self alloc] initWithString:stampStr error:error];
}

- (NSString *)prettyUrl {
    ServerStamp stamp = convert_stamp(self);
    return convert_string(stamp.pretty_url(false));
}

- (NSString *)prettierUrl {
    ServerStamp stamp = convert_stamp(self);
    return convert_string(stamp.pretty_url(true));
}

- (NSString *)stringValue {
    ServerStamp stamp = convert_stamp(self);
    return convert_string(stamp.str());
}

+ (BOOL)supportsSecureCoding {
    return YES;
}

@end

@implementation AGDnsUtils

static auto dnsUtilsLogger = Logger{"AGDnsUtils"};

static std::optional<std::string> verifyCertificate(CertificateVerificationEvent event) {
    return [AGDnsProxy verifyCertificate: &event log: dnsUtilsLogger];
}

+ (NSError *)testUpstream:(AGDnsUpstream *)opts
                timeoutMs:(NSUInteger)timeoutMs
            ipv6Available:(BOOL)ipv6Available
                  offline:(BOOL)offline
{
    auto error = ag::dns::test_upstream(convert_upstream(opts), Millis{timeoutMs}, ipv6Available, verifyCertificate, offline);
    if (error) {
        return [NSError errorWithDomain: AGDnsProxyErrorDomain
                                   code: AGDPE_TEST_UPSTREAM_ERROR
                               userInfo: @{NSLocalizedDescriptionKey: convert_string(error->str())}];
    }
    return nil;
}

@end

@implementation AGDnsRuleTemplate {
    ag::dns::DnsFilter::RuleTemplate _template;
    ag::dns::DnsRequestProcessedEvent _event;
}

- (instancetype)initWithTemplate:(ag::dns::DnsFilter::RuleTemplate)t
                           event:(ag::dns::DnsRequestProcessedEvent)e {
    self = [super init];
    if (self) {
        _template = std::move(t);
        _event = std::move(e);
    }
    return self;
}

- (NSString *)description {
    return convert_string(_template.text);
}

- (NSString *)generateRuleWithOptions:(NSUInteger)options {
    return convert_string(ag::dns::DnsFilter::generate_rule(_template, _event, options));
}

@end

@implementation AGDnsFilteringLogAction
- (instancetype)initWithAction:(const ag::dns::DnsFilter::FilteringLogAction &)action
                         event:(const ag::dns::DnsRequestProcessedEvent &)event {
    self = [super init];
    if (self) {
        _allowedOptions = (NSUInteger) action.allowed_options;
        _requiredOptions = (NSUInteger) action.required_options;
        _blocking = (BOOL) action.blocking;
        auto *templates = [NSMutableArray arrayWithCapacity:action.templates.size()];
        for (auto &t: action.templates) {
            [templates addObject:[[AGDnsRuleTemplate alloc] initWithTemplate:t event:event]];
        }
        _templates = templates;
    }
    return self;
}

+ (instancetype)actionFromEvent:(AGDnsRequestProcessedEvent *)event {
    auto cevent = [event nativeEvent];
    if (auto action = ag::dns::DnsFilter::suggest_action(cevent)) {
        return [[AGDnsFilteringLogAction alloc] initWithAction:*action event:cevent];
    }
    return nil;
}

@end

@implementation AGDnsMessageInfo
@end
