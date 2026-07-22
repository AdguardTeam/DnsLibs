# cmake/sccache_msvc.cmake
#
# Make MSVC builds safe to route through a compiler launcher such as sccache
# (or ccache) by switching the debug-information format from /Zi (a shared
# per-target .pdb) to /Z7 (CodeView records embedded in each .obj) whenever
# CMAKE_C_COMPILER_LAUNCHER / CMAKE_CXX_COMPILER_LAUNCHER is set.
#
# Why this is needed:
#   sccache silently discards /FS -- the flag that serializes PDB writes via
#   mspdbsrv -- so parallel cl.exe invocations under Ninja all open the same
#   per-target .pdb for write and fail with C1041 ("cannot open program
#   database ... if multiple CL.EXE write to the same .PDB file, please use
#   /FS"). /Z7 embeds the debug info in the .obj instead of writing a shared
#   PDB, eliminating the contention; the /Fd name is then used only by the
#   linker, which runs serially.
#
#   https://github.com/mozilla/sccache/issues/1012
#   https://github.com/mozilla/sccache/issues/2320  (same C1041 symptom)
#
# What this module does:
#   1. Sets AG_MSVC_DEBUG_INFO_FORMAT to "/Z7" when a launcher is active and
#      "/Zi" otherwise, so a top-level CMakeLists.txt can append it to its
#      explicit CMAKE_C/CXX_FLAGS line (e.g. capi's
#      `set(CMAKE_C_FLAGS "... /MT ${AG_MSVC_DEBUG_INFO_FORMAT} /EHs-c-")`).
#   2. Replaces "/Zi" with "/Z7" in CMake's standard C/CXX flag variables so
#      compiler-identification defaults (and any inherited /Zi) do not
#      reintroduce a shared PDB after this module runs.
#
# Usage: include() this after project() (so the compiler-identification
# flags that populate CMAKE_C_FLAGS etc. are already in place) and before any
# explicit CMAKE_C/CXX_FLAGS line that appends AG_MSVC_DEBUG_INFO_FORMAT.
# A no-op for non-MSVC toolchains and when no launcher is configured; safe to
# include unconditionally.

if (NOT MSVC)
    return()
endif ()

if (CMAKE_C_COMPILER_LAUNCHER OR CMAKE_CXX_COMPILER_LAUNCHER)
    set(AG_MSVC_DEBUG_INFO_FORMAT "/Z7")

    # CMake populates CMAKE_<LANG>_FLAGS_<CONFIG> with /Zi for Debug and
    # RelWithDebInfo by default; replace every occurrence in every standard
    # configuration (including MinSizeRel, which a user may have added /Zi to)
    # so no shared PDB is left in any configuration's flags.
    foreach (AgFlag
            CMAKE_C_FLAGS
            CMAKE_C_FLAGS_DEBUG
            CMAKE_C_FLAGS_RELEASE
            CMAKE_C_FLAGS_RELWITHDEBINFO
            CMAKE_C_FLAGS_MINSIZEREL
            CMAKE_CXX_FLAGS
            CMAKE_CXX_FLAGS_DEBUG
            CMAKE_CXX_FLAGS_RELEASE
            CMAKE_CXX_FLAGS_RELWITHDEBINFO
            CMAKE_CXX_FLAGS_MINSIZEREL)
        string(REPLACE "/Zi" "/Z7" ${AgFlag} "${${AgFlag}}")
    endforeach ()
else ()
    set(AG_MSVC_DEBUG_INFO_FORMAT "/Zi")
endif ()
