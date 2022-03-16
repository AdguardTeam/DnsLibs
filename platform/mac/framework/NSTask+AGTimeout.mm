#import <common/logger.h>
#import "NSTask+AGTimeout.h"


#define MS_IN_NS INT64_C(1000000)

@implementation NSTask(AGTimeout)

static ag::Logger logger{"NSTask+Timeout"};

- (BOOL)waitUntilExitOrInterruptAfterTimeoutMs:(int64_t)millis {
    __block BOOL ret = NO;
    dispatch_queue_t queue = dispatch_get_global_queue(0, 0);
    dispatch_group_t serviceGroup = dispatch_group_create();
    dispatch_source_t exitWaitSource = dispatch_source_create(DISPATCH_SOURCE_TYPE_PROC, (uintptr_t) self.processIdentifier, DISPATCH_PROC_EXIT, queue);
    dispatch_source_t exitTimeoutSource = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, queue);
    dispatch_source_set_event_handler(exitWaitSource, ^{
        [self waitUntilExit];
        dispatch_source_cancel(exitTimeoutSource);
        ret = YES;
    });
    dispatch_source_set_event_handler(exitTimeoutSource, ^{
        errlog(logger, "waitUntilExitOrInterruptAfterTimeoutMs timeout reached");
        if ([self isRunning]) {
            [self interrupt];
        }
        dispatch_source_cancel(exitTimeoutSource);
    });
    dispatch_group_enter(serviceGroup); // exitTimeoutSource
    dispatch_source_set_cancel_handler(exitTimeoutSource, ^{
        dispatch_group_leave(serviceGroup); // exitTimeoutSource
    });
    dispatch_source_set_timer(exitTimeoutSource, dispatch_time(DISPATCH_TIME_NOW, millis * MS_IN_NS), DISPATCH_TIME_FOREVER, 0);
    dispatch_resume(exitTimeoutSource);
    dispatch_resume(exitWaitSource);

    dispatch_group_wait(serviceGroup, DISPATCH_TIME_FOREVER);
    return ret;
}

@end
