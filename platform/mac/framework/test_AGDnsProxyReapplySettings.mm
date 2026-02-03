#include <AGDnsProxy/AGDnsProxy.h>
#include <Foundation/Foundation.h>
#include <dispatch/dispatch.h>

#include <array>

// Helper to create DNS query for a given domain (A record)
NSData* createDnsQuery(NSString *domain) {
    NSMutableData *query = [NSMutableData data];
    
    // DNS header: ID=0x1234, flags=0x0120 (standard query, recursion desired)
    uint8_t header[] = {0x12, 0x34, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    [query appendBytes:header length:sizeof(header)];
    
    // Encode domain name (e.g., "example.org" -> 0x07 "example" 0x03 "org" 0x00)
    NSArray *labels = [domain componentsSeparatedByString:@"."];
    for (NSString *label in labels) {
        uint8_t len = (uint8_t)[label length];
        [query appendBytes:&len length:1];
        [query appendData:[label dataUsingEncoding:NSASCIIStringEncoding]];
    }
    uint8_t zero = 0;
    [query appendBytes:&zero length:1];
    
    // Query type (A) and class (IN)
    uint8_t typeClass[] = {0x00, 0x01, 0x00, 0x01};
    [query appendBytes:typeClass length:sizeof(typeClass)];
    
    return query;
}

static int gRequestsProcessed = 0;
static BOOL gLastRequestBlocked = NO;
static NSString *gLastDomain = nil;
static dispatch_semaphore_t gCallbackSemaphore = nil;

// Events handler using block-based API
void setupEventsHandler(AGDnsProxyEvents *events) {
    events.onRequestProcessed = ^(const AGDnsRequestProcessedEvent *event) {
        gRequestsProcessed++;
        gLastDomain = event.domain;
        
        // Check if request was blocked (REFUSED or has blocking rules)
        gLastRequestBlocked = (event.rules && event.rules.count > 0) || 
                             ([event.status isEqualToString:@"REFUSED"]);
        
        // Signal that callback was invoked
        if (gCallbackSemaphore) {
            dispatch_semaphore_signal(gCallbackSemaphore);
        }
    };
}

AGDnsProxyConfig* createConfigWithFilter(BOOL includeFilter, NSString *domain) {
    auto *upstream = [[AGDnsUpstream alloc] init];
    upstream.address = @"8.8.8.8";
    upstream.id = 42;
    
    auto *config = [AGDnsProxyConfig getDefault];
    config.upstreams = @[upstream];
    config.upstreamTimeoutMs = 5000;
    config.enableServfailOnUpstreamsFailure = YES;
    
    if (includeFilter) {
        // Add blocking filter for specified domain
        auto *filter = [[AGDnsFilterParams alloc] init];
        filter.id = 1;
        filter.data = domain;
        filter.inMemory = YES;
        
        config.filters = @[filter];
    }
    
    return config;
}

NSData* sendQueryAndWait(AGDnsProxy *proxy, NSString *domain, int timeoutSeconds) {
    dispatch_group_t group = dispatch_group_create();
    dispatch_group_enter(group);
    
    __block NSData *result = nil;
    NSData *query = createDnsQuery(domain);
    
    [proxy handleMessage:query
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

// Test 1: reapplyUpstreams=true, reapplyFilters=false
// Filters should be preserved when reapplyFilters=false
int test_reapply_upstreams_only() {
    @autoreleasepool {
        NSLog(@"Test 1: reapplyUpstreams=true, reapplyFilters=false");
        
        NSString *testDomain = @"test1.example.org";
        
        gCallbackSemaphore = dispatch_semaphore_create(0);
        gRequestsProcessed = 0;
        gLastRequestBlocked = NO;
        
        // Create proxy with filter that blocks test1.example.org
        auto *config = createConfigWithFilter(YES, testDomain);
        auto *eventsHandler = [[AGDnsProxyEvents alloc] init];
        setupEventsHandler(eventsHandler);
        
        NSError *error = nil;
        auto *proxy = [[AGDnsProxy alloc] initWithConfig:config handler:eventsHandler error:&error];
        if (error || !proxy) {
            NSLog(@"ERROR: Failed to create proxy: %@", error);
            return 1;
        }

        // Send query - should be blocked
        NSData *response1 = sendQueryAndWait(proxy, testDomain, 10);
        if (!response1) {
            NSLog(@"ERROR: No response received for first query");
            [proxy stop];
            return 2;
        }
        
        if (dispatch_semaphore_wait(gCallbackSemaphore, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC))) {
            NSLog(@"ERROR: Callback timeout for first query");
            [proxy stop];
            return 2;
        }
        
        if (!gLastRequestBlocked) {
            NSLog(@"ERROR: First request should have been blocked but wasn't");
            [proxy stop];
            return 3;
        }

        // Reapply with new upstream but preserve filters
        auto *newConfig = createConfigWithFilter(NO, nil);  // No filter in new config
        auto *newUpstream = [[AGDnsUpstream alloc] init];
        newUpstream.address = @"1.1.1.1";  // Change upstream
        newUpstream.id = 43;
        newConfig.upstreams = @[newUpstream];
        
        BOOL success = [proxy reapplySettings:newConfig options:AGDnsProxyReapplySettings error:&error];
        if (!success) {
            NSLog(@"ERROR: reapplySettings failed: %@", error);
            [proxy stop];
            return 4;
        }

        // Send query again - should still be blocked (filters preserved)
        gLastRequestBlocked = NO;
        NSData *response2 = sendQueryAndWait(proxy, testDomain, 10);
        if (!response2) {
            NSLog(@"ERROR: No response received for second query");
            [proxy stop];
            return 5;
        }
        
        if (dispatch_semaphore_wait(gCallbackSemaphore, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC))) {
            NSLog(@"ERROR: Callback timeout for second query");
            [proxy stop];
            return 5;
        }
        
        if (!gLastRequestBlocked) {
            NSLog(@"ERROR: Second request should still be blocked (filters preserved)");
            [proxy stop];
            return 6;
        }

        [proxy stop];
        NSLog(@"Test 1 passed");
        return 0;
    }
}

// Test 2: reapplyUpstreams=true, reapplyFilters=true
// Filters should be updated when reapplyFilters=true
int test_reapply_both() {
    @autoreleasepool {
        NSLog(@"Test 2: reapplyUpstreams=true, reapplyFilters=true");
        
        NSString *testDomain = @"test2.example.org";
        
        gCallbackSemaphore = dispatch_semaphore_create(0);
        gRequestsProcessed = 0;
        gLastRequestBlocked = NO;
        
        // Create proxy with filter
        auto *config = createConfigWithFilter(YES, testDomain);
        auto *eventsHandler = [[AGDnsProxyEvents alloc] init];
        setupEventsHandler(eventsHandler);
        
        NSError *error = nil;
        auto *proxy = [[AGDnsProxy alloc] initWithConfig:config handler:eventsHandler error:&error];
        if (error || !proxy) {
            NSLog(@"ERROR: Failed to create proxy: %@", error);
            return 7;
        }

        // Send query - should be blocked
        NSData *response1 = sendQueryAndWait(proxy, testDomain, 10);
        if (!response1) {
            NSLog(@"ERROR: No response received for first query");
            [proxy stop];
            return 8;
        }
        
        if (dispatch_semaphore_wait(gCallbackSemaphore, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC))) {
            NSLog(@"ERROR: Callback timeout for first query");
            [proxy stop];
            return 8;
        }
        
        if (!gLastRequestBlocked) {
            NSLog(@"ERROR: First request should have been blocked");
            [proxy stop];
            return 9;
        }

        // Reapply without filters (both upstreams and filters)
        auto *newConfig = createConfigWithFilter(NO, nil);
        BOOL success = [proxy reapplySettings:newConfig options:(AGDnsProxyReapplySettings | AGDnsProxyReapplyFilters) error:&error];
        if (!success) {
            NSLog(@"ERROR: reapplySettings failed: %@", error);
            [proxy stop];
            return 10;
        }

        // Send query again - should NOT be blocked (filters removed)
        gLastRequestBlocked = YES;
        NSData *response2 = sendQueryAndWait(proxy, testDomain, 10);
        if (!response2) {
            NSLog(@"ERROR: No response received for second query");
            [proxy stop];
            return 11;
        }
        
        if (dispatch_semaphore_wait(gCallbackSemaphore, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC))) {
            NSLog(@"ERROR: Callback timeout for second query");
            [proxy stop];
            return 11;
        }
        
        if (gLastRequestBlocked) {
            NSLog(@"ERROR: Second request should NOT be blocked (filters removed)");
            [proxy stop];
            return 12;
        }

        [proxy stop];
        NSLog(@"Test 2 passed");
        return 0;
    }
}

// Test 3: reapplyUpstreams=false, reapplyFilters=true
// Only filters should be updated, upstreams preserved
int test_reapply_filters_only() {
    @autoreleasepool {
        NSLog(@"Test 3: reapplyUpstreams=false, reapplyFilters=true");
        
        NSString *testDomain = @"test3.example.org";
        
        gCallbackSemaphore = dispatch_semaphore_create(0);
        gRequestsProcessed = 0;
        gLastRequestBlocked = NO;
        
        // Create proxy WITHOUT filter initially
        auto *config = createConfigWithFilter(NO, nil);
        auto *eventsHandler = [[AGDnsProxyEvents alloc] init];
        setupEventsHandler(eventsHandler);
        
        NSError *error = nil;
        auto *proxy = [[AGDnsProxy alloc] initWithConfig:config handler:eventsHandler error:&error];
        if (error || !proxy) {
            NSLog(@"ERROR: Failed to create proxy: %@", error);
            return 13;
        }

        // Send query - should NOT be blocked (no filter)
        NSData *response1 = sendQueryAndWait(proxy, testDomain, 10);
        if (!response1) {
            NSLog(@"ERROR: No response received for first query");
            [proxy stop];
            return 14;
        }
        
        if (dispatch_semaphore_wait(gCallbackSemaphore, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC))) {
            NSLog(@"ERROR: Callback timeout for first query");
            [proxy stop];
            return 14;
        }
        
        if (gLastRequestBlocked) {
            NSLog(@"ERROR: First request should NOT be blocked (no filter)");
            [proxy stop];
            return 15;
        }

        // Reapply with filter (filters only, preserve upstreams)
        auto *newConfig = createConfigWithFilter(YES, testDomain);
        BOOL success = [proxy reapplySettings:newConfig options:AGDnsProxyReapplyFilters error:&error];
        if (!success) {
            NSLog(@"ERROR: reapplySettings failed: %@", error);
            [proxy stop];
            return 16;
        }

        // Send query again - should be blocked (filter added)
        gLastRequestBlocked = NO;
        NSData *response2 = sendQueryAndWait(proxy, testDomain, 10);
        if (!response2) {
            NSLog(@"ERROR: No response received for second query");
            [proxy stop];
            return 17;
        }
        
        if (dispatch_semaphore_wait(gCallbackSemaphore, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC))) {
            NSLog(@"ERROR: Callback timeout for second query");
            [proxy stop];
            return 17;
        }
        
        if (!gLastRequestBlocked) {
            NSLog(@"ERROR: Second request should be blocked (filter added)");
            [proxy stop];
            return 18;
        }

        [proxy stop];
        NSLog(@"Test 3 passed");
        return 0;
    }
}

// Test 4: reapplyUpstreams=false, reapplyFilters=false
// Nothing should change (no-op)
int test_reapply_noop() {
    @autoreleasepool {
        NSLog(@"Test 4: reapplyUpstreams=false, reapplyFilters=false (no-op)");
        
        NSString *testDomain = @"test4.example.org";
        
        gCallbackSemaphore = dispatch_semaphore_create(0);
        gRequestsProcessed = 0;
        gLastRequestBlocked = NO;
        
        // Create proxy with filter
        auto *config = createConfigWithFilter(YES, testDomain);
        auto *eventsHandler = [[AGDnsProxyEvents alloc] init];
        setupEventsHandler(eventsHandler);
        
        NSError *error = nil;
        auto *proxy = [[AGDnsProxy alloc] initWithConfig:config handler:eventsHandler error:&error];
        if (error || !proxy) {
            NSLog(@"ERROR: Failed to create proxy: %@", error);
            return 19;
        }

        // Send query - should be blocked
        NSData *response1 = sendQueryAndWait(proxy, testDomain, 10);
        if (!response1) {
            NSLog(@"ERROR: No response received for first query");
            [proxy stop];
            return 20;
        }
        
        if (dispatch_semaphore_wait(gCallbackSemaphore, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC))) {
            NSLog(@"ERROR: Callback timeout for first query");
            [proxy stop];
            return 20;
        }
        
        if (!gLastRequestBlocked) {
            NSLog(@"ERROR: First request should be blocked");
            [proxy stop];
            return 21;
        }

        // No-op reapply (both flags false)
        auto *newConfig = createConfigWithFilter(NO, nil);  // Different config but won't be applied
        BOOL success = [proxy reapplySettings:newConfig options:AGDnsProxyReapplyNone error:&error];
        if (!success) {
            NSLog(@"ERROR: reapplySettings failed: %@", error);
            [proxy stop];
            return 22;
        }

        // Send query again - should still be blocked (nothing changed)
        gLastRequestBlocked = NO;
        NSData *response2 = sendQueryAndWait(proxy, testDomain, 10);
        if (!response2) {
            NSLog(@"ERROR: No response received for second query");
            [proxy stop];
            return 23;
        }
        
        if (dispatch_semaphore_wait(gCallbackSemaphore, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC))) {
            NSLog(@"ERROR: Callback timeout for second query");
            [proxy stop];
            return 23;
        }
        
        if (!gLastRequestBlocked) {
            NSLog(@"ERROR: Second request should still be blocked (no-op, filter still active)");
            [proxy stop];
            return 24;
        }

        [proxy stop];
        NSLog(@"Test 4 passed");
        return 0;
    }
}

int main() {
    @autoreleasepool {
        [AGDnsLogger setLevel:AGDLLTrace];
        
        int result = 0;
        
        if ((result = test_reapply_upstreams_only()) != 0) {
            NSLog(@"ERROR: Test suite failed at test 1");
            return result;
        }
        
        if ((result = test_reapply_both()) != 0) {
            NSLog(@"ERROR: Test suite failed at test 2");
            return result;
        }
        
        if ((result = test_reapply_filters_only()) != 0) {
            NSLog(@"ERROR: Test suite failed at test 3");
            return result;
        }
        
        if ((result = test_reapply_noop()) != 0) {
            NSLog(@"ERROR: Test suite failed at test 4");
            return result;
        }
        
        NSLog(@"All tests passed!");
        return 0;
    }
}
