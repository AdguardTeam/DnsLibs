# Building on Windows

Prerequisites: Conan, Visual Studio 2022 >=17.6.1 (MSVC >=19.36).

Please see how to use Conan in the main README.

To build the DLL:

* Open the Visual Studio "Developer Command Prompt" and run the following commands.
* `rm -rf cmake-build-win && mkdir cmake-build-win && cd cmake-build-win`
* `vcvarsamd64_x86` to build a 32-bit library or `vcvars64` to build a 64-bit library.
* `cmake -DCMAKE_BUILD_TYPE=Release -G Ninja ..`
* `ninja AdguardDns` to build a 32-bit library or `ninja AdguardDns64` to build a 64-bit library.

To run tests:

* Build the DLL and run the following commands in the same command prompt. 
* `ninja tests && ctest`
