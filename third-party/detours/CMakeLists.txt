cmake_minimum_required(VERSION 3.10)

project(detours)

set(DETOURS_DIR ./detours)
set(DETOURS_SRCS
        ${DETOURS_DIR}/src/detours.cpp
        ${DETOURS_DIR}/src/modules.cpp
        ${DETOURS_DIR}/src/disasm.cpp
        ${DETOURS_DIR}/src/image.cpp
        ${DETOURS_DIR}/src/creatwth.cpp
        ${DETOURS_DIR}/src/disolx86.cpp
        ${DETOURS_DIR}/src/disolx64.cpp
        ${DETOURS_DIR}/src/disolia64.cpp
        ${DETOURS_DIR}/src/disolarm.cpp
        ${DETOURS_DIR}/src/disolarm64.cpp
        )

add_library(detours STATIC EXCLUDE_FROM_ALL ${DETOURS_SRCS})
target_include_directories(detours PUBLIC ${DETOURS_DIR}/src)
