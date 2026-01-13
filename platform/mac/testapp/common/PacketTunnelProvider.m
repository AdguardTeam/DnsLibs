#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#import "PacketTunnelProvider.h"
#import <AGDnsProxy/AGDnsProxy.h>
#import <AGDnsProxy/AGDnsTunListener.h>

@implementation AGTunnel {
    void (^onStarted)(NSError * __nullable error);

    AGDnsProxy *proxy;
    AGDnsTunListener *tunListener;
}

- (void) dealloc
{}

- (NSArray *) getFilterFilesList: (NSError * _Nullable *) error
{
    NSMutableArray<NSString *> *list = [[NSMutableArray alloc] init];

    NSFileManager *manager = [NSFileManager defaultManager];
    NSString *folder = [[NSBundle mainBundle] resourcePath];
    NSDirectoryEnumerator *direnum = [manager enumeratorAtPath: folder];

    NSString *name;
    while (name = [direnum nextObject]) {
        NSLog(@"getFilterFilesList considering %@", name);
        if ([[name pathExtension] isEqualToString:@"txt"]) {
            NSLog(@"getFilterFilesList adding %@", name);
            NSString *fullPath = [folder stringByAppendingFormat: @"/%@", name];
            [list addObject: fullPath];
        }
    }

    NSLog(@"getFilterFilesList ok");
    return list;
}

// This function is called by OS when the associated VPN connection is being started.
- (void) startTunnelWithOptions: (nullable NSDictionary<NSString *,NSObject *> *) options
        completionHandler: (void (^)(NSError * __nullable error)) completionHandler
{
    NSLog(@"startTunnelWithOptions");

    [AGLogger setLevel: AGLL_TRACE];
    [AGLogger setCallback:
        ^(AGLogLevel lvl, const char *msg, int length) {
            NSLog(@"%.*s", (int)length, msg);
        }];

    self->onStarted = completionHandler;

    NEPacketTunnelNetworkSettings *settings =
        [[NEPacketTunnelNetworkSettings alloc] initWithTunnelRemoteAddress:@"127.1.1.1"];

    NEDNSSettings *dns = [[NEDNSSettings alloc] initWithServers: @[
        @"198.18.0.1",
        @"2001:ad00:ad00::ad00"]];
    dns.matchDomains = @[ @"" ];
    settings.DNSSettings = dns;

    NEIPv4Settings *ipv4 =
        [[NEIPv4Settings alloc] initWithAddresses:@[@"172.16.209.2"] subnetMasks:@[@"255.255.255.252"]];
    ipv4.excludedRoutes = @[[NEIPv4Route defaultRoute]];

    NEIPv4Route* dnsProxyIpv4Route =
        [[NEIPv4Route alloc] initWithDestinationAddress:@"198.18.0.1" subnetMask:@"255.255.255.255"];
    ipv4.includedRoutes = @[dnsProxyIpv4Route];

    settings.IPv4Settings = ipv4;

    NEIPv6Settings *ipv6 =
        [[NEIPv6Settings alloc] initWithAddresses:@[@"fd12:1:1:1::2"] networkPrefixLengths:@[@(64)]];
    ipv6.excludedRoutes = @[[NEIPv6Route defaultRoute]];

    NEIPv6Route* dnsProxyIpv6Route =
         [[NEIPv6Route alloc] initWithDestinationAddress:@"2001:ad00:ad00::ad00"
                                     networkPrefixLength:@(128)];
    ipv6.includedRoutes = @[dnsProxyIpv6Route];

    settings.IPv6Settings = ipv6;

    __unsafe_unretained AGTunnel *wself = self;
    [self setTunnelNetworkSettings: settings completionHandler: ^(NSError * _Nullable error)
    {
        NSLog(@"setTunnelNetworkSettings");
        AGTunnel *sself = wself;
        if (sself == nil)
            return;
        [sself onInit: error];
    }];
}

// This function is called by OS when the associated VPN connection is being stopped.
- (void) stopTunnelWithReason: (NEProviderStopReason) reason
        completionHandler: (void (^)(void)) completionHandler
{
    NSLog(@"stopTunnelWithReason: %u", (int)reason);
    if (self->tunListener) {
        [self->tunListener stop];
        self->tunListener = nil;
    }
    completionHandler();
}

// VPN connection is started.
// Start reading packets from TUN interface.
// Notify the caller of NEVPNConnection.startVPNTunnelWithOptions().
- (void) onInit: (NSError *) error
{
    NSLog(@"Initializing tunnel...");
    if (error != nil) {
        self->onStarted(error);
        return;
    }

    NSArray *filterFiles = [self getFilterFilesList: &error];
    if (filterFiles == nil) {
        self->onStarted(error);
        return;
    }

    __block NSMutableArray<AGDnsFilterParams *> *filters = [NSMutableArray arrayWithCapacity:filterFiles.count];
    [filterFiles enumerateObjectsUsingBlock:^(id object, NSUInteger idx, BOOL *stop) {
        AGDnsFilterParams *filter = [[AGDnsFilterParams alloc] init];
        filter.id = idx;
        filter.data = object;
        filter.inMemory = NO;
        [filters addObject: filter];
    }];
    AGDnsProxyConfig *cfg = [AGDnsProxyConfig getDefault];
    AGDnsUpstream *upstream = [[AGDnsUpstream alloc] init];
    upstream.address = @"tls://94.140.14.14";
    upstream.timeoutMs = 10000;
    upstream.id = 42;
    cfg.upstreams = @[upstream];

    AGDnsProxyEvents *events = [[AGDnsProxyEvents alloc] init];
    events.onRequestProcessed = ^(const AGDnsRequestProcessedEvent *event) {
        NSLog(@"onRequestProcessed domain: %@", event.domain);
        NSLog(@"onRequestProcessed answer: %@", event.answer);
        NSLog(@"onRequestProcessed error: %@", event.error);
        NSLog(@"onRequestProcessed upstream: %@", event.upstreamId);
    };

    NSError *proxy_err = nil;
    self->proxy = [[AGDnsProxy alloc] initWithConfig: cfg handler: events error: &proxy_err];
    if (self->proxy == nil) {
        NSLog(@"failed to initialize dns proxy");
        if (proxy_err) {
            self->onStarted(proxy_err);
        } else {
            NSDictionary *info = [NSDictionary dictionaryWithObject: @[@"failed to initialize dns proxy"]
                forKey: NSLocalizedDescriptionKey];
            NSError *e = [NSError errorWithDomain: @"ag tunnel" code: -1 userInfo: info];
            self->onStarted(e);
        }
        return;
    }
    if (proxy_err) {
        // if we got here, the proxy had been initialized with warnings
        // handle the the proxy initialization warning (proxy_err)
    }

    [self startPacketHandling];
    self->onStarted(nil);
}

// Initialize TunListener for UDP + TCP DNS support
- (void) startPacketHandling
{
    NSError *error = nil;
    // Create TunListener in external mode using NEPacketTunnelFlow
    self->tunListener = [[AGDnsTunListener alloc]
        initWithTunFd:nil                    // External mode
         orTunnelFlow:self.packetFlow        // Use NEPacketTunnelFlow API
                  mtu:0                      // Use default MTU
       messageHandler:^(NSData *request, AGDnsTunListenerReplyHandler replyHandler) {
           [self->proxy handleMessage:request
                             withInfo:nil
                withCompletionHandler:replyHandler];
       }
                error:&error];

    if (error || !self->tunListener) {
        NSLog(@"Failed to initialize TunListener: %@", error);
        return;
    }

    NSLog(@"TunListener initialized successfully (UDP + TCP DNS support enabled)");
}

@end
