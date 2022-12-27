#include <gtest/gtest.h>

#include "dns/dnsfilter/dnsfilter.h"

using namespace ag::dns;

TEST(FilteringLogAction, Block) {
    DnsRequestProcessedEvent event;
    event.domain = "sub.dom.ain.example.co.uk";
    event.type = "AAAA";

    auto action = DnsFilter::suggest_action(event);

    ASSERT_TRUE(action);
    ASSERT_TRUE(action->blocking);
    ASSERT_EQ(DnsFilter::RGO_IMPORTANT | DnsFilter::RGO_DNSTYPE, action->allowed_options);
    ASSERT_EQ(0, action->required_options);
    ASSERT_EQ(2, action->templates.size());

    ASSERT_EQ("||sub.dom.ain.example.co.uk^$dnstype=AAAA,important",
            DnsFilter::generate_rule(action->templates[0], event, DnsFilter::RGO_DNSTYPE | DnsFilter::RGO_IMPORTANT));
    ASSERT_EQ("||example.co.uk^$dnstype=AAAA,important",
            DnsFilter::generate_rule(action->templates[1], event, DnsFilter::RGO_DNSTYPE | DnsFilter::RGO_IMPORTANT));
}

TEST(FilteringLogAction, UnBlock) {
    DnsRequestProcessedEvent event;
    event.domain = "sub.dom.ain.example.co.uk";
    event.type = "AAAA";

    event.rules.emplace_back("|sub.dom.ain.example.co.uk$important");

    auto action = DnsFilter::suggest_action(event);

    ASSERT_TRUE(action);
    ASSERT_FALSE(action->blocking);
    ASSERT_EQ(DnsFilter::RGO_IMPORTANT | DnsFilter::RGO_DNSTYPE, action->allowed_options);
    ASSERT_EQ(DnsFilter::RGO_IMPORTANT, action->required_options);
    ASSERT_EQ(2, action->templates.size());

    ASSERT_EQ("@@||sub.dom.ain.example.co.uk^$important",
            DnsFilter::generate_rule(action->templates[0], event, DnsFilter::RGO_IMPORTANT));
    ASSERT_EQ("@@||example.co.uk^$important",
            DnsFilter::generate_rule(action->templates[1], event, DnsFilter::RGO_IMPORTANT));
}

TEST(FilteringLogAction, BlockImportantException) {
    DnsRequestProcessedEvent event;
    event.domain = "sub.dom.ain.example.co.uk";
    event.type = "AAAA";

    event.rules.emplace_back("@@sub.dom.ain.example.co.uk$important");

    auto action = DnsFilter::suggest_action(event);

    ASSERT_TRUE(action);
    ASSERT_TRUE(action->blocking);
    ASSERT_EQ(0, action->allowed_options);
    ASSERT_EQ(0, action->required_options);
    ASSERT_EQ(1, action->templates.size());

    ASSERT_EQ("@@sub.dom.ain.example.co.uk$important,badfilter",
            DnsFilter::generate_rule(action->templates[0], event, 0));
}

TEST(FilteringLogAction, UnBlockHosts) {
    DnsRequestProcessedEvent event;
    event.domain = "sub.dom.ain.example.co.uk";
    event.type = "AAAA";

    event.rules.emplace_back("127.0.0.1 sub.dom.ain.example.co.uk");

    auto action = DnsFilter::suggest_action(event);

    ASSERT_TRUE(action);
    ASSERT_FALSE(action->blocking);
    ASSERT_EQ(DnsFilter::RGO_IMPORTANT | DnsFilter::RGO_DNSTYPE, action->allowed_options);
    ASSERT_EQ(0, action->required_options);
    ASSERT_EQ(2, action->templates.size());

    ASSERT_EQ("@@||sub.dom.ain.example.co.uk^$dnstype=AAAA,important",
            DnsFilter::generate_rule(action->templates[0], event, DnsFilter::RGO_DNSTYPE | DnsFilter::RGO_IMPORTANT));
    ASSERT_EQ("@@||example.co.uk^$dnstype=AAAA,important",
            DnsFilter::generate_rule(action->templates[1], event, DnsFilter::RGO_DNSTYPE | DnsFilter::RGO_IMPORTANT));
}

TEST(FilteringLogAction, Etld1) {
    DnsRequestProcessedEvent event;
    event.domain = "myhostname";
    event.type = "AAAA";

    auto action = DnsFilter::suggest_action(event);

    ASSERT_TRUE(action);
    ASSERT_TRUE(action->blocking);
    ASSERT_EQ(DnsFilter::RGO_IMPORTANT | DnsFilter::RGO_DNSTYPE, action->allowed_options);
    ASSERT_EQ(0, action->required_options);
    ASSERT_EQ(1, action->templates.size());

    ASSERT_EQ("||myhostname^$dnstype=AAAA,important",
            DnsFilter::generate_rule(action->templates[0], event, DnsFilter::RGO_DNSTYPE | DnsFilter::RGO_IMPORTANT));
}

TEST(FilteringLogAction, Etld2) {
    DnsRequestProcessedEvent event;
    event.domain = "myhostname.local";
    event.type = "AAAA";

    auto action = DnsFilter::suggest_action(event);

    ASSERT_TRUE(action);
    ASSERT_TRUE(action->blocking);
    ASSERT_EQ(DnsFilter::RGO_IMPORTANT | DnsFilter::RGO_DNSTYPE, action->allowed_options);
    ASSERT_EQ(0, action->required_options);
    ASSERT_EQ(1, action->templates.size());

    ASSERT_EQ("||myhostname.local^$dnstype=AAAA,important",
            DnsFilter::generate_rule(action->templates[0], event, DnsFilter::RGO_DNSTYPE | DnsFilter::RGO_IMPORTANT));
}

TEST(FilteringLogAction, Etld3) {
    DnsRequestProcessedEvent event;
    event.domain = "toaster.myhostname.local";
    event.type = "AAAA";

    auto action = DnsFilter::suggest_action(event);

    ASSERT_TRUE(action);
    ASSERT_TRUE(action->blocking);
    ASSERT_EQ(DnsFilter::RGO_IMPORTANT | DnsFilter::RGO_DNSTYPE, action->allowed_options);
    ASSERT_EQ(0, action->required_options);
    ASSERT_EQ(2, action->templates.size());

    ASSERT_EQ("||toaster.myhostname.local^$dnstype=AAAA,important",
            DnsFilter::generate_rule(action->templates[0], event, DnsFilter::RGO_DNSTYPE | DnsFilter::RGO_IMPORTANT));
    ASSERT_EQ("||myhostname.local^$dnstype=AAAA,important",
            DnsFilter::generate_rule(action->templates[1], event, DnsFilter::RGO_DNSTYPE | DnsFilter::RGO_IMPORTANT));
}

TEST(FilteringLogAction, Etld4) {
    DnsRequestProcessedEvent event;
    event.domain = "toaster.myhostname.com";
    event.type = "AAAA";

    auto action = DnsFilter::suggest_action(event);

    ASSERT_TRUE(action);
    ASSERT_TRUE(action->blocking);
    ASSERT_EQ(DnsFilter::RGO_IMPORTANT | DnsFilter::RGO_DNSTYPE, action->allowed_options);
    ASSERT_EQ(0, action->required_options);
    ASSERT_EQ(2, action->templates.size());

    ASSERT_EQ("||toaster.myhostname.com^$dnstype=AAAA,important",
            DnsFilter::generate_rule(action->templates[0], event, DnsFilter::RGO_DNSTYPE | DnsFilter::RGO_IMPORTANT));
    ASSERT_EQ("||myhostname.com^$dnstype=AAAA,important",
            DnsFilter::generate_rule(action->templates[1], event, DnsFilter::RGO_DNSTYPE | DnsFilter::RGO_IMPORTANT));
}

TEST(FilteringLogAction, Etld5) {
    DnsRequestProcessedEvent event;
    event.domain = "switch.toaster.myhostname.com";
    event.type = "AAAA";

    auto action = DnsFilter::suggest_action(event);

    ASSERT_TRUE(action);
    ASSERT_TRUE(action->blocking);
    ASSERT_EQ(DnsFilter::RGO_IMPORTANT | DnsFilter::RGO_DNSTYPE, action->allowed_options);
    ASSERT_EQ(0, action->required_options);
    ASSERT_EQ(2, action->templates.size());

    ASSERT_EQ("||switch.toaster.myhostname.com^$dnstype=AAAA,important",
            DnsFilter::generate_rule(action->templates[0], event, DnsFilter::RGO_DNSTYPE | DnsFilter::RGO_IMPORTANT));
    ASSERT_EQ("||myhostname.com^$dnstype=AAAA,important",
            DnsFilter::generate_rule(action->templates[1], event, DnsFilter::RGO_DNSTYPE | DnsFilter::RGO_IMPORTANT));
}

TEST(FilteringLogAction, NoType) {
    DnsRequestProcessedEvent event;
    event.domain = "switch.toaster.myhostname.com";

    auto action = DnsFilter::suggest_action(event);

    ASSERT_TRUE(action);
    ASSERT_TRUE(action->blocking);
    ASSERT_EQ(DnsFilter::RGO_IMPORTANT, action->allowed_options);
    ASSERT_EQ(0, action->required_options);
    ASSERT_EQ(2, action->templates.size());

    ASSERT_EQ("||switch.toaster.myhostname.com^", DnsFilter::generate_rule(action->templates[0], event, 0));
    ASSERT_EQ("||myhostname.com^", DnsFilter::generate_rule(action->templates[1], event, 0));
}
