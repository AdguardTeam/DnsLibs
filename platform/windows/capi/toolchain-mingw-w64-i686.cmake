# The name of the target operating system
SET(CMAKE_SYSTEM_NAME Windows)

# Not set by cmake for mingw, used by boringssl's CMakeLists.txt
set(CMAKE_SYSTEM_PROCESSOR "i686")

# Silence `unknown conversion type character...` errors
add_definitions(-D__USE_MINGW_ANSI_STDIO)

# Set the correct nasm output format
set(CMAKE_ASM_NASM_FLAGS "${CMAKE_ASM_NASM_FLAGS} -f win32")

# Choose an appropriate compiler prefix (see http://mingw-w64.sourceforge.net/)
set(CL_MINGW_COMPILER_PREFIX "${CMAKE_SYSTEM_PROCESSOR}-w64-mingw32")

# Which compilers to use for C and C++
find_program(CMAKE_C_COMPILER NAMES "${CL_MINGW_COMPILER_PREFIX}-gcc")
find_program(CMAKE_CXX_COMPILER NAMES "${CL_MINGW_COMPILER_PREFIX}-g++")

# adjust the default behaviour of the FIND_XXX() commands:
# search headers and libraries in the target environment, search
# programs in the host environment
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
