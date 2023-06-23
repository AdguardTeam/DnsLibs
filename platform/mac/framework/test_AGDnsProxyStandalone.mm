/**
 * @file test_AGDnsProxyStandalone.mm
 * @brief Usage example
 */

#include <AGDnsProxy/AGDnsProxy.h>
#include <Foundation/Foundation.h>

int main() {
    [AGLogger setLevel:AGLL_TRACE];
    auto *listener = [[AGListenerSettings alloc] init];
    listener.address = @"::";
    listener.port = 5321;
    listener.proto = AGLP_UDP;
    listener.persistent = NO;
    listener.idleTimeoutMs = 10;

    auto *upstream = [[AGDnsUpstream alloc] init];
    upstream.address = @"tls://dns.adguard-dns.com";
    upstream.bootstrap = @[@"1.1.1.1"];
    upstream.serverIp = nil;
    upstream.id = 42;
    upstream.outboundInterfaceName = nil;
    upstream.fingerprints = @[@"pUZw/ajtE73tCpUV810KK+2TfhAKpignA8s7hyggVew="]; // dns.adguard-dns.com public key fingerprint

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

    auto *handler = [[AGDnsProxyEvents alloc] init];
    NSError *error;
    auto *proxy = [[AGDnsProxy alloc] initWithConfig:config handler:handler error:&error];
    if (error || !proxy) {
        NSLog(@"%@", error);
        [proxy stop];
        return 1;
    }
    while (getchar() != 's') {
        ;
    }
    [proxy stop];
    return 0;
}
