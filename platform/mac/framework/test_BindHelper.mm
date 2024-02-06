#include <AGDnsProxy/AGDnsProxy.h>
#include <Foundation/Foundation.h>

/// Test that listeners bind to localhost@53 for TCP/UDP and IPv4/IPv6
int main() {
    auto *listener1 = [[AGDnsListenerSettings alloc] init];
    listener1.address = @"127.0.0.1";
    listener1.port = 53;
    listener1.proto = AGLP_UDP;
    listener1.persistent = NO;
    listener1.idleTimeoutMs = 0;

    auto *listener2 = [[AGDnsListenerSettings alloc] init];
    listener2.address = @"127.0.0.1";
    listener2.port = 53;
    listener2.proto = AGLP_TCP;
    listener2.persistent = NO;
    listener2.idleTimeoutMs = 10000;

    auto *listener3 = [[AGDnsListenerSettings alloc] init];
    listener3.address = @"::1";
    listener3.port = 53;
    listener3.proto = AGLP_UDP;
    listener3.persistent = NO;
    listener3.idleTimeoutMs = 0;

    auto *listener4 = [[AGDnsListenerSettings alloc] init];
    listener4.address = @"::1";
    listener4.port = 53;
    listener4.proto = AGLP_TCP;
    listener4.persistent = NO;
    listener4.idleTimeoutMs = 10000;

    auto *listeners = @[listener1, listener2, listener3, listener4];

    auto *upstream = [[AGDnsUpstream alloc] init];
    upstream.address = @"94.140.14.14";
    upstream.bootstrap = nil;
    upstream.serverIp = nil;
    upstream.id = 42;
    upstream.outboundInterfaceName = nil;

    auto *config = [AGDnsProxyConfig getDefault];
    config.upstreams = @[upstream];
    config.listeners = listeners;
    config.helperPath = @""; // Insert path to adguard-tun-helper
    config.upstreamTimeoutMs = 1000;

    auto *handler = [AGDnsProxyEvents new];
    NSError *error;
    auto *proxy = [[AGDnsProxy alloc] initWithConfig:config handler:handler error:&error];
    if (!proxy) {
        NSLog(@"%@", error);
        return 1;
    }
    while (getchar() != 's') {
        ;
    }
    [proxy stop];
    return 0;
}
