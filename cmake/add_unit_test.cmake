include(GoogleTest)

if(NOT TARGET tests)
    add_custom_target(tests)
endif(NOT TARGET tests)

# `EXPAND_GTEST=TRUE` registers each gtest case as its own CTest entry via
# `gtest_discover_tests()`, so per-case skips/failures (e.g. REQUIRE_INTEGRATION()
# gates) surface individually in the `make test` summary. Prefer TRUE.
#
# Use FALSE only for binaries with parametrized cases (TEST_P /
# WithParamInterface): their expanded CTest names are often opaque and unreadable,
# and FALSE collapses the whole binary into one CTest entry (per-case skips are
# then absorbed into the binary's overall result).
function(add_unit_test TEST_NAME TEST_DIR EXTRA_INCLUDES IS_GTEST EXPAND_GTEST)
    set(FILE_NO_EXT ${TEST_DIR}/${TEST_NAME})
    if (EXISTS "${FILE_NO_EXT}.cpp")
        set(FILE_PATH ${FILE_NO_EXT}.cpp)
    elseif(EXISTS "${FILE_NO_EXT}.c")
        set(FILE_PATH ${FILE_NO_EXT}.c)
    else()
        message(FATAL_ERROR "Cannot find source file for test: ${TEST_NAME} (directory=${TEST_DIR})")
    endif()

    add_executable(${TEST_NAME} EXCLUDE_FROM_ALL ${FILE_PATH})
    foreach(INC ${EXTRA_INCLUDES})
        target_include_directories(${TEST_NAME} PRIVATE ${INC})
    endforeach()

    add_dependencies(tests ${TEST_NAME})

    if (${IS_GTEST})
        find_package(GTest REQUIRED)
        target_link_libraries(${TEST_NAME} PRIVATE gtest::gtest)
    endif()

    if (${EXPAND_GTEST} AND NOT ${CMAKE_CROSSCOMPILING})
        gtest_discover_tests(${TEST_NAME} PROPERTIES DISCOVERY_TIMEOUT 30)
    else()
        add_test(${TEST_NAME} ${TEST_NAME})
    endif()
endfunction()
