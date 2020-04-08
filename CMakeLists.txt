cmake_minimum_required(VERSION 3.6)
project(agdns C CXX)

set(CMAKE_POLICY_DEFAULT_CMP0063 NEW) # allows visibility=hidden for static targets for subprojects
cmake_policy(SET CMP0063 NEW) # allows visibility=hidden for static targets for this project

set(CMAKE_C_VISIBILITY_PRESET hidden)
set(CMAKE_CXX_VISIBILITY_PRESET hidden)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

if (MSVC)
    set(CMAKE_SHARED_LINKER_FLAGS_DEBUG "${CMAKE_SHARED_LINKER_FLAGS_DEBUG} /DEBUG /OPT:REF")
    set(CMAKE_SHARED_LINKER_FLAGS_RELEASE "${CMAKE_SHARED_LINKER_FLAGS_RELEASE} /DEBUG /OPT:REF")
    set(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} /DEBUG /OPT:REF")
    set(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} /DEBUG /OPT:REF")

    set(CompilerFlags
            CMAKE_CXX_FLAGS
            CMAKE_CXX_FLAGS_DEBUG
            CMAKE_CXX_FLAGS_RELEASE
            CMAKE_C_FLAGS
            CMAKE_C_FLAGS_DEBUG
            CMAKE_C_FLAGS_RELEASE
            )
    foreach (CompilerFlag ${CompilerFlags})
        string(REPLACE "/MDd" "/MT" ${CompilerFlag} "${${CompilerFlag}}")
        string(REPLACE "-MDd" "-MT" ${CompilerFlag} "${${CompilerFlag}}")
        string(REPLACE "/MTd" "/MT" ${CompilerFlag} "${${CompilerFlag}}")
        string(REPLACE "-MTd" "-MT" ${CompilerFlag} "${${CompilerFlag}}")
        string(REPLACE "/MD" "/MT" ${CompilerFlag} "${${CompilerFlag}}")
        string(REPLACE "-MD" "-MT" ${CompilerFlag} "${${CompilerFlag}}")
        string(REPLACE "/RTC1" "" ${CompilerFlag} "${${CompilerFlag}}")
    endforeach ()

    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /MT /Zi /EHs-c-")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /MT /Zi /EHs-c- /std:c++latest")
else ()
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-strict-aliasing -fno-exceptions")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-strict-aliasing -fno-exceptions")
endif ()

add_definitions(-DFMT_EXCEPTIONS=0)

if (WIN32)
    # Minimum supported Windows API is 6.1 (Windows 7)
    add_definitions(-D_WIN32_WINNT=0x0601)
    add_definitions(-D__USE_MINGW_ANSI_STDIO=1 -D_CRT_SECURE_NO_WARNINGS -D_CRT_NONSTDC_NO_DEPRECATE)

    set(CMAKE_SHARED_LIBRARY_PREFIX "")
    set(CMAKE_SHARED_LIBRARY_SUFFIX ".dll")

    if (NOT MSVC) # WIN32 and not msvc => must be MinGW, link statically
        link_libraries(-static)
    endif ()
endif ()

add_subdirectory(dnsfilter)
add_subdirectory(tls)
add_subdirectory(upstream)
add_subdirectory(proxy)
enable_testing()
