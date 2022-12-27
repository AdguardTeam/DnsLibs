#include <AGDnsProxy/AGDnsProxy.h>
#include <cstdlib>

#define ASSERT(x_) do { if (!(x_)) abort(); } while (0)

int main() {
    auto *event = [[AGDnsRequestProcessedEvent alloc] init];
    event.domain = @"example.org";
    event.type = @"TEXT";
    event.rules = @[@"||example.org^$important"];
    auto *action = [AGFilteringLogAction actionFromEvent:event];
    ASSERT(action);
    ASSERT(action.blocking == NO);
    ASSERT(action.requiredOptions == AGRGOImportant);
    ASSERT(action.allowedOptions == (AGRGOImportant | AGRGODnstype));
    ASSERT(action.templates.count == 1);
    ASSERT([@"@@||example.org^$dnstype=TEXT,important" isEqualToString:
            [action.templates[0] generateRuleWithOptions:(AGRGOImportant | AGRGODnstype)]]);
    return 0;
}
