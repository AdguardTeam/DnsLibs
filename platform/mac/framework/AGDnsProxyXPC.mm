#import "AGDnsProxyXPC.h"

#pragma GCC visibility push(hidden)
#import "common/logger.h"
#pragma GCC visibility pop

static ag::Logger gLogger{"AGDnsProxyXPCImpl"};

@implementation AGDnsProxyXPCImpl {
    dispatch_queue_t _queue;
    AGDnsProxy *_proxy;
    AGDnsProxyEvents *_events;
}

- (instancetype)initWithConfig:(AGDnsProxyConfig *)config
                        events:(id<AGDnsProxyEventsXPC>)events
                         error:(NSError **)error {
    self = [super init];
    if (self) {
        _queue = dispatch_queue_create("com.adguard.dnslibs.AGDnsProxyXPCImpl.queue", DISPATCH_QUEUE_SERIAL);
        auto *dnsEvents = [[AGDnsProxyEvents alloc] init];
        dnsEvents.onRequestProcessed = ^(const AGDnsRequestProcessedEvent *event) {
            [events onRequestProcessed:event];
        };
        _events = dnsEvents;
        _proxy = [[AGDnsProxy alloc] initWithConfig:config handler:_events error:error];
        if (!_proxy) {
            return nil;
        }
    }
    return self;
}

+ (NSXPCInterface *)xpcInterface {
    auto *iface = [NSXPCInterface interfaceWithProtocol:@protocol(AGDnsProxyXPC)];
    return iface;
}

- (void)reconfig:(AGDnsProxyConfig *)config
        completionHandler:(void (^)(NSError *))handler {
    dispatch_async(_queue, ^{
        NSError *error = nil;
        [_proxy stop];
        _proxy = nil;
        _proxy = [[AGDnsProxy alloc] initWithConfig:config handler:_events error:&error];
        handler(error);
    });
}

- (void)handlePacket:(NSData *)packet completionHandler:(void (^)(NSData *))completionHandler {
    dispatch_async(_queue, ^{
        [_proxy handlePacket:packet completionHandler:completionHandler];
    });
}

- (void)stopWithCompletionHandler:(void (^)())handler {
    dispatch_async(_queue, ^{
        [_proxy stop];
        handler();
    });
}

- (AGDnsProxy *)unwrap {
    __block AGDnsProxy *proxy;
    dispatch_sync(_queue, ^{
        proxy = _proxy;
    });
    return proxy;
}

@end
