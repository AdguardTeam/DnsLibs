#include <gtest/gtest.h>
#include <memory>

#include "dns/proxy/tun_listener.h"

using namespace ag::dns;

TEST(TunListenerTest, InvalidParameters) {
    TunListener listener;
    
    // Test invalid MTU (negative)
    {
        auto result = listener.init(3, -1,
            [](ag::Uint8View, TunListener::Completion) {});
        ASSERT_TRUE(result);
        EXPECT_EQ(result->value(), TunListener::IE_INVALID_MTU);
    }

    // Test null callback
    {
        TunListener::RequestCallback null_callback;
        auto result = listener.init(3, 1500, null_callback);
        ASSERT_TRUE(result);
        EXPECT_EQ(result->value(), TunListener::IE_INVALID_CALLBACK);
    }

    // Test external mode without output callback
    {
        auto result = listener.init(-1, 1500,
            [](ag::Uint8View, TunListener::Completion) {});
        ASSERT_TRUE(result);
        EXPECT_EQ(result->value(), TunListener::IE_INVALID_CALLBACK);
    }

}

TEST(TunListenerTest, MultipleDeinitSafe) {
    TunListener listener;
    
    // Deinit without init should be safe
    EXPECT_NO_THROW(listener.deinit());
    EXPECT_NO_THROW(listener.deinit());
}

TEST(TunListenerTest, DefaultMTU) {
    TunListener listener;
    
    // MTU = 0 should be accepted and use default
    auto result = listener.init(999, 0,
        [](ag::Uint8View, TunListener::Completion) {});
    
    // Will fail because fd 999 is not a real TUN device, but MTU validation should pass
    // The error should be TCPIP_INIT_FAILED, not INVALID_MTU
    if (result) {
        EXPECT_EQ(result->value(), TunListener::IE_TCPIP_INIT_FAILED);
    }
    listener.deinit();
}
