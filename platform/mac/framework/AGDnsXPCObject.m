#import "AGDnsXPCObject.h"

@implementation AGDnsXPCObject

+ (NSSet *)allowedClasses {
    static NSSet *classes;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        classes = [[NSSet alloc] initWithObjects:AGDnsXPCObject.class, NSData.class, NSString.class, NSArray.class,
                                                 NSSet.class, NSDictionary.class, NSNumber.class, nil];
    });
    return classes;
}

@end
