#include <exception>

/**
 * Since `/EHs-c-a- /D_HAS_EXCEPTIONS=0` does NOT in fact completely disable stack unwinding and exception handling,
 * and does not cause `std::terminate` to be called when an exception is thrown, override `_CxxThrowException` to
 * call `std::terminate`. This works because apparently it is defined in its own object in the CRT and we link
 * the CRT statically.
 */
extern "C" __declspec(noreturn) void __stdcall _CxxThrowException(void *, _ThrowInfo *) {
    std::terminate();
}
