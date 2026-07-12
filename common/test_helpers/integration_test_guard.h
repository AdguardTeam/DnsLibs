#pragma once

#include <cstdlib>

#include <gtest/gtest.h>

namespace ag::test {

// True only when DNSLIBS_INTEGRATION_TESTS is set in the environment.
// Real-network protocol tests are opted into via REQUIRE_INTEGRATION().
inline bool integration_tests_enabled() {
    return std::getenv("DNSLIBS_INTEGRATION_TESTS") != nullptr;
}

} // namespace ag::test

// Skip the enclosing test unless integration tests are explicitly enabled.
//
// Works both in ordinary gtest bodies (GTEST_SKIP() does `return`) and in
// coroutine test bodies created via "common/gtest_coro.h" (where GTEST_SKIP()
// is redefined to `co_return`). The trailing `<<` message is only evaluated on
// the failure path, so it is safe to use here.
#define REQUIRE_INTEGRATION()                                                                                          \
    do {                                                                                                               \
        if (!ag::test::integration_tests_enabled()) {                                                                  \
            GTEST_SKIP() << "Set DNSLIBS_INTEGRATION_TESTS=1 to run real-network protocol tests";                      \
        }                                                                                                              \
    } while (0)
