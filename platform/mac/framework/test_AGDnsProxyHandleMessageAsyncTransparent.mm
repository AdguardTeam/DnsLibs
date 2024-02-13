/**
 * @brief Test asynchronous transparent message handling
 */

#include <AGDnsProxy/AGDnsProxy.h>

#include <Foundation/Foundation.h>
#include <dispatch/dispatch.h>

#include <array>

static constexpr uint8_t QUERY[] = {
        0x92, 0xaa, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x6f, 0x72, 0x67,
        0x00, 0x00, 0x01, 0x00, 0x01
};

int main() {
    [AGDnsLogger setLevel:AGDLLTrace];

    auto *upstream = [[AGDnsUpstream alloc] init];
    upstream.address = @"1.2.3.4"; // blackhole, intentional
    upstream.id = 42;

    auto *config = [AGDnsProxyConfig getDefault];
    config.upstreams = @[upstream];
    config.upstreamTimeoutMs = 1000;
    config.enableServfailOnUpstreamsFailure = NO;

    auto *handler = [[AGDnsProxyEvents alloc] init];
    NSError *error;
    auto *proxy = [[AGDnsProxy alloc] initWithConfig:config handler:handler error:&error];
    if (error || !proxy) {
        NSLog(@"%@", error);
        [proxy stop];
        return 1;
    }

    auto *info = [[AGDnsMessageInfo alloc] init];
    info.transparent = YES;

    dispatch_group_t group = dispatch_group_create();
    dispatch_group_enter(group);

    __block NSData *result;

    [proxy handleMessage:[NSData dataWithBytes:QUERY length:std::size(QUERY)]
                withInfo:info withCompletionHandler:^(NSData *result0) {
                result = result0;
                dispatch_group_leave(group);
            }];

    if (dispatch_group_wait(group, dispatch_time(DISPATCH_TIME_NOW, 10 * NSEC_PER_SEC))) {
        return 2;
    }

    if (!result.bytes || !result.length) {
        return 3;
    }

    [proxy stop];
    return 0;
}
