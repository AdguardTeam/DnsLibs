# Building on Windows

Prerequisites: Conan, Visual Studio 2019 (MSVC >= 19.28).

Please see how to use Conan in the main README.

To build the DLL:

* Open the Visual Studio "Developer Command Prompt".
* `rm -rf cmake-build-win && mkdir cmake-build-win && cd cmake-build-win`
* `vcvars32`
* `cmake -DCMAKE_BUILD_TYPE=Release -G Ninja ..`
* `ninja AdguardDns`

To run tests:
 
* `ninja tests && ctest`
