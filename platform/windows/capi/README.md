# After checkout
Initialize submodules: (Warning: `-f` will destroy your local changes in submodules)
```
git submodule init && git submodule update -f
```

# Building on Windows

## Natively
Prerequisites: LLVM 9.0.1, Visual Studio 2017, cmake, ninja, Go, perl, nasm, git.

Don't put LLVM in your path: cmake may pick up the wrong RC.

* `rm -rf cmake-build-win && mkdir cmake-build-win && cd cmake-build-win`
* `vcvars32` (important)
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

## Using [MSYS2](https://www.msys2.org): 
* `pacman -Syyuu` (follow their instructions)
* `pacman -S mingw-w64-i686-toolchain mingw-w64-i686-go mingw-w64-i686-perl mingw-w64-i686-nasm mingw-w64-i686-cmake mingw-w64-i686-ninja git` (accept default choices)
* `/mingw32.exe` (important)
* `rm -rf cmake-build-mingw && mkdir cmake-build-mingw && cd cmake-build-mingw`
* `cmake -DCMAKE_USE_OPENSSL=ON -DCMAKE_BUILD_TYPE=Release -G Ninja ..`
* `ninja AdguardDns capi_test -j 12` (where 12 is the number of processors on your system)
* `ctest -R capi_test`

# Building on UNIX for Windows
Prerequisites: mingw-w64, cmake, git, perl, Go, nasm.
* `rm -rf cmake-build-mingw && mkdir cmake-build-mingw && cd cmake-build-mingw`
* `cmake -DCMAKE_TOOLCHAIN_FILE=../toolchain-mingw-w64-i686.cmake -DCMAKE_USE_OPENSSL=ON -DCMAKE_BUILD_TYPE=Release ..`
* `make AdguardDns capi_test -j 12` (where 12 is the number of processors on your system)
* `ctest -R capi_test`
