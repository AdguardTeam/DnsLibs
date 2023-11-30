#import "NSTask+AGUtils.h"

@implementation NSTask(AGUtils)

- (dispatch_group_t)launchWithGroupAndReturnError:(NSError **)error {
    void (^oldTerminationHandler)(NSTask *) = self.terminationHandler;
    dispatch_group_t group = dispatch_group_create();
    dispatch_group_enter(group);
    self.terminationHandler = ^(NSTask *){
        dispatch_group_leave(group);
    };
    if (![self launchAndReturnError:error]) {
        dispatch_group_leave(group);
        return nil;
    }
    if (oldTerminationHandler) {
        dispatch_group_notify(group, dispatch_get_global_queue(0, 0), ^{
            oldTerminationHandler(self);
        });
    }
    return group;
}

@end
