#import "AGDnsProxyXPC.h"

#pragma GCC visibility push(hidden)
#import "common/logger.h"
#pragma GCC visibility pop

static ag::Logger gLogger{"AGDnsProxyXPCImpl"};

@implementation AGDnsProxyXPCImpl {
    dispatch_queue_t _queue;
    AGDnsProxy *_proxy;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        _queue = dispatch_queue_create("com.adguard.dnslibs.AGDnsProxyXPCImpl.queue", DISPATCH_QUEUE_SERIAL);
    }
    return self;
}

+ (NSXPCInterface *)xpcInterface {
    auto *callbacksIface = [NSXPCInterface interfaceWithProtocol:@protocol(AGDnsProxyEventsXPC)];

    auto *iface = [NSXPCInterface interfaceWithProtocol:@protocol(AGDnsProxyXPC)];
    [iface setInterface:callbacksIface
            forSelector:@selector(initWithConfig:eventsHandler:completionHandler:)
          argumentIndex:1
                ofReply:NO];

    return iface;
}

- (void)initWithConfig:(AGDnsProxyConfig *)config
         eventsHandler:(id <AGDnsProxyEventsXPC>)eventsHandler
     completionHandler:(void (^)(NSError *))handler {
    dispatch_async(_queue, ^{
        auto *events = [[AGDnsProxyEvents alloc] init];
        events.onRequestProcessed = ^(const AGDnsRequestProcessedEvent *event) {
            [eventsHandler onRequestProcessed:event];
        };
        NSError *error = nil;
        _proxy = [[AGDnsProxy alloc] initWithConfig:config handler:events error:&error];
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

@end
