#include <AGDnsProxy/AGDnsProxy.h>
#include <Foundation/Foundation.h>

/// Test that we don't crash when `[AGDnsProxy initWithConfig]` fails because listeners couldn't be initialized
static int regressTestListenerFailsInit() {
    // This listener MUST cause initialization to fail
    auto *listener = [[AGListenerSettings alloc] init];
    listener.address = @"asdf";
    listener.port = 0;
    listener.proto = AGLP_UDP;
    listener.persistent = NO;
    listener.idleTimeoutMs = 10;

    auto *upstream = [[AGDnsUpstream alloc] init];
    upstream.address = @"1.1.1.1";
    upstream.bootstrap = nil;
    upstream.serverIp = nil;
    upstream.id = 42;
    upstream.outboundInterfaceName = nil;

    auto *config = [AGDnsProxyConfig getDefault];
    config.upstreams = @[upstream];
    config.listeners = @[listener];
    config.upstreamTimeoutMs = 1000;

    auto *handler = [[AGDnsProxyEvents alloc] init];
    NSError *error;
    auto *proxy = [[AGDnsProxy alloc] initWithConfig:config handler:handler error:&error];
    if (!error || proxy) {
        [proxy stop];
        return 1;
    }
    return 0;
}

int main() {
    return regressTestListenerFailsInit();
}
