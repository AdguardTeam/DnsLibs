#import <AGDnsProxy/AGDnsProxy.h>
#import <AGDnsProxy/AGDnsProxyXPC.h>

static constexpr uint8_t REQUEST[] = "\x45\x00\x00\x39\x1b\x32\x00\x00\x40\x11\x92\xbb\xc0\xa8\x0a\x1d\x01\x01\x01\x01"
                                     "\xfd\xb0\x00\x35\x00\x25\xf6\x0d\x6c\x55\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00"
                                     "\x07\x65\x78\x61\x6d\x70\x6c\x65\x03\x6f\x72\x67\x00\x00\x01\x00\x01";

static int gEventsCounter;
static id <AGDnsProxyXPC> gDnsProxyXPC;

@interface EventsHandler : NSObject <AGDnsProxyEventsXPC>

@end

@implementation EventsHandler
- (void)onRequestProcessed:(const AGDnsRequestProcessedEvent *)event {
    if (![event.domain isEqualToString:@"example.org."]) {
        exit(4);
    }
    [gDnsProxyXPC stopWithCompletionHandler:^{
        exit(0);
    }];
}
@end

@interface Delegate : NSObject <NSXPCListenerDelegate>
@end

@implementation Delegate {
    AGDnsProxyXPCImpl *_impl;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        _impl = [[AGDnsProxyXPCImpl alloc] init];
    }
    return self;
}

- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)newConnection {
    newConnection.exportedInterface = [AGDnsProxyXPCImpl xpcInterface];
    newConnection.exportedObject = _impl;
    [newConnection resume];
    return YES;
}

@end

int main() {
    [AGLogger setLevel:AGLL_TRACE];
    auto *listener = [[AGListenerSettings alloc] init];
    listener.address = @"::";
    listener.port = 53;
    listener.proto = AGLP_UDP;
    listener.persistent = NO;
    listener.idleTimeoutMs = 10;

    auto *upstream = [[AGDnsUpstream alloc] init];
    upstream.address = @"tls://1.1.1.1";
    upstream.bootstrap = @[];
    upstream.serverIp = nil;
    upstream.id = 42;
    upstream.outboundInterfaceName = nil;

    auto *fallback = [[AGDnsUpstream alloc] init];
    fallback.address = @"1.1.1.1";
    fallback.bootstrap = nil;
    fallback.serverIp = nil;
    fallback.id = 43;
    fallback.outboundInterfaceName = nil;

    auto *config = [AGDnsProxyConfig getDefault];
    config.upstreams = @[upstream];
    config.fallbacks = @[fallback];
    config.listeners = @[listener];
    config.upstreamTimeoutMs = 1000;

    auto *xpcListener = [NSXPCListener anonymousListener];
    auto *delegate = [[Delegate alloc] init];
    xpcListener.delegate = delegate;
    [xpcListener resume];

    auto *xpcConnection = [[NSXPCConnection alloc] initWithListenerEndpoint:xpcListener.endpoint];
    xpcConnection.remoteObjectInterface = [AGDnsProxyXPCImpl xpcInterface];
    [xpcConnection resume];

    auto *eventsHandler = [[EventsHandler alloc] init];

    dispatch_async(dispatch_get_main_queue(), ^{
        gDnsProxyXPC = xpcConnection.remoteObjectProxy;
        [gDnsProxyXPC initWithConfig:config eventsHandler:eventsHandler completionHandler:^(NSError *error) {
            if (error) {
                exit(1);
            }
            [gDnsProxyXPC handlePacket:[NSData dataWithBytes:REQUEST length:sizeof(REQUEST) - 1] completionHandler:^(NSData *response) {
                if (response == nil || response.length == 0) {
                    exit(2);
                }
            }];
        }];
    });

    dispatch_main();
}
