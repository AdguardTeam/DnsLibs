#import <Foundation/Foundation.h>

/** Marker interface for classes that can be sent over XPC. */
@interface AGDnsXPCObject : NSObject

/** Return the set of classes that are allowed to be sent over XPC. */
+(NSSet *)allowedClasses;

@end