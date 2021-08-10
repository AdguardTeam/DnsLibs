# Building on Windows

Prerequisites: Conan, LLVM, Visual Studio 2017/Build Tools, cmake, ninja, git.

Please see how to use conan in the main README.

* `rm -rf cmake-build-win && mkdir cmake-build-win && cd cmake-build-win`
* `vcvars32` (important, run from Visual Studio developer console)
```
cmake -DCMAKE_BUILD_TYPE=Release ^
-DCMAKE_USE_OPENSSL=ON ^
-DCMAKE_C_COMPILER=<path to clang-cl> ^
-DCMAKE_CXX_COMPILER=<path to clang-cl> ^
-DCMAKE_C_FLAGS=--target=i686-pc-windows-msvc ^
-DCMAKE_CXX_FLAGS=--target=i686-pc-windows-msvc ^
-G Ninja ..
```
* `ninja AdguardDns capi_test -j 12` (where 12 is the number of processors on your system)
* `ctest -R capi_test`
