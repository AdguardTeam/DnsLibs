#include <AGDnsProxy/AGDnsProxy.h>
#include <Foundation/Foundation.h>
#include <dispatch/dispatch.h>

#include <array>

// DNS query for example.org (A record)
static constexpr uint8_t QUERY[] = {
    0x12, 0x34, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x6f, 0x72, 0x67,
    0x00, 0x00, 0x01, 0x00, 0x01
};

static int gRequestsProcessed = 0;
static BOOL gLastRequestBlocked = NO;
static NSString *gLastDomain = nil;

@interface TestEventsHandler : NSObject <AGDnsProxyEvents>
@end

@implementation TestEventsHandler
- (void)onRequestProcessed:(const AGDnsRequestProcessedEvent *)event {
    gRequestsProcessed++;
    gLastDomain = event.domain;
    
    // Check if request was blocked (REFUSED or has blocking rules)
    gLastRequestBlocked = (event.rules && event.rules.count > 0) || 
                         ([event.status isEqualToString:@"REFUSED"]);
}
@end

AGDnsProxyConfig* createConfigWithFilter(BOOL includeFilter) {
    auto *upstream = [[AGDnsUpstream alloc] init];
    upstream.address = @"8.8.8.8";
    upstream.id = 42;
    
    auto *config = [AGDnsProxyConfig getDefault];
    config.upstreams = @[upstream];
    config.upstreamTimeoutMs = 5000;
    config.enableServfailOnUpstreamsFailure = YES;
    
    if (includeFilter) {
        // Add blocking filter for example.org
        auto *filter = [[AGDnsFilterParams alloc] init];
        filter.id = 1;
        filter.data = @"example.org";  // Block example.org
        filter.inMemory = YES;
        
        config.filterParams = [[AGDnsFilterEngineParams alloc] init];
        config.filterParams.filters = @[filter];
    }
    
    return config;
}

NSData* sendQueryAndWait(AGDnsProxy *proxy, int timeoutSeconds) {
    dispatch_group_t group = dispatch_group_create();
    dispatch_group_enter(group);
    
    __block NSData *result = nil;
    
    [proxy handleMessage:[NSData dataWithBytes:QUERY length:std::size(QUERY)]
                withInfo:nil 
       withCompletionHandler:^(NSData *response) {
           result = response;
           dispatch_group_leave(group);
       }];
    
    dispatch_time_t timeout = dispatch_time(DISPATCH_TIME_NOW, timeoutSeconds * NSEC_PER_SEC);
    if (dispatch_group_wait(group, timeout)) {
        NSLog(@"Query timeout after %d seconds", timeoutSeconds);
        return nil;
    }
    
    return result;
}

int main() {
    @autoreleasepool {
        [AGDnsLogger setLevel:AGDLLTrace];
        
        // Reset counters
        gRequestsProcessed = 0;
        gLastRequestBlocked = NO;
        
        // Create proxy with filter that blocks example.org
        auto *config = createConfigWithFilter(YES);
        auto *eventsHandler = [[TestEventsHandler alloc] init];
        
        NSError *error = nil;
        auto *proxy = [[AGDnsProxy alloc] initWithConfig:config handler:eventsHandler error:&error];
        if (error || !proxy) {
            NSLog(@"%@", error);
            return 1;
        }

        // Send query - should be blocked
        NSData *response1 = sendQueryAndWait(proxy, 10);
        if (!response1) {
            NSLog(@"No response received for first query");
            [proxy stop];
            return 2;
        }
        
        if (!gLastRequestBlocked) {
            NSLog(@"First request should have been blocked but wasn't");
            [proxy stop];
            return 3;
        }

        // Fast reapply without filters (reapplyFilters = NO)
        auto *newConfig1 = createConfigWithFilter(NO);  // No filter in new config
        auto *newUpstream = [[AGDnsUpstream alloc] init];
        newUpstream.address = @"1.1.1.1";  // Change upstream
        newUpstream.id = 43;
        newConfig1.upstreams = @[newUpstream];
        
        BOOL success = [proxy reapplySettings:newConfig1 reapplyFilters:NO error:&error];
        if (!success) {
            NSLog(@"%@", error);
            [proxy stop];
            return 4;
        }

        // Send query again - should still be blocked (filters preserved)
        gLastRequestBlocked = NO;  // Reset
        NSData *response2 = sendQueryAndWait(proxy, 10);
        if (!response2) {
            NSLog(@"No response received for second query");
            [proxy stop];
            return 5;
        }
        
        if (!gLastRequestBlocked) {
            NSLog(@"Second request should still be blocked (filters preserved)");
            [proxy stop];
            return 6;
        }

        // Full reapply without filters (reapplyFilters = YES)
        auto *newConfig2 = createConfigWithFilter(NO);  // No filter
        success = [proxy reapplySettings:newConfig2 reapplyFilters:YES error:&error];
        if (!success) {
            NSLog(@"%@", error);
            [proxy stop];
            return 7;
        }

        // Send query again - should NOT be blocked (filters removed)
        gLastRequestBlocked = YES;  // Reset to opposite
        NSData *response3 = sendQueryAndWait(proxy, 10);
        if (!response3) {
            NSLog(@"No response received for third query");
            [proxy stop];
            return 8;
        }
        
        if (gLastRequestBlocked) {
            NSLog(@"Third request should NOT be blocked (filters removed)");
            [proxy stop];
            return 9;
        }

        // Cleanup
        [proxy stop];
        return 0;
    }
}
