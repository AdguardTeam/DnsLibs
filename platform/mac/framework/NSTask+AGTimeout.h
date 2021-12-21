#import <Foundation/Foundation.h>

@interface NSTask(AGTimeout)

/**
 * Wait until process exit with timeout and interrupts task if timeout is reached
 * @param millis Timeout in milliseconds
 * @return YES is task was exited and NO if task was terminated due to timeout
 */
- (BOOL)waitUntilExitOrInterruptAfterTimeoutMs:(int64_t)millis;

@end
