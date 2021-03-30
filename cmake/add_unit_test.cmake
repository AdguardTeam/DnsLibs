include(GoogleTest)

if(NOT TARGET tests)
    add_custom_target(tests)
endif(NOT TARGET tests)

if (NOT TARGET gtest_main)
    add_subdirectory(${THIRD_PARTY_DIR}/googletest ${CMAKE_BINARY_DIR}/third-party/googletest)
    set_property(TARGET gtest PROPERTY EXCLUDE_FROM_ALL ON)
    set_property(TARGET gtest_main PROPERTY EXCLUDE_FROM_ALL ON)
endif (NOT TARGET gtest_main)

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
        target_link_libraries(${TEST_NAME} PRIVATE gtest gtest_main)
    endif()

    if (${EXPAND_GTEST})
        gtest_discover_tests(${TEST_NAME})
    else()
        add_test(${TEST_NAME} ${TEST_NAME})
    endif()
endfunction()
