#pragma once

#import <Foundation/Foundation.h>

@interface NSTask(AGUtils)

/**
 * Launch task and return dispatch group for this task.<p/>
 *
 * You may use `dispatch_group_notify` for adding termination handler to this group
 * and `dispatch_group_wait` for synchronous waiting for task termination.<p/>
 *
 * This method sets terminationHandler to task, so it is guaranteed to be tracked by libdispatch, not on run loop.
 *
 * @param error Pointer to variable where task launch error will be written
 * @return Dispatch group for this task
 */
- (dispatch_group_t)launchWithGroupAndReturnError:(NSError **)error;

@end
