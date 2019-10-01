# AdGuard C++ DNS libraries

##

```
git submodule init
git submodule update
```

## Code rules 

(TODO: write them)

- C++17
- underscore naming for classes, members, functions and variables
- ag:: namespace
- use already written third-party libraries (Google Test for tests, etc.)
- use submodules
- use CMake

Every subproject consists of the following directories and files:
- `include/` - public headers
- `src/` - source code files and provate headers
- `test/` - tests and its data
- `CMakeLists.txt` - cmake build config. Should be self-configurable.

Root project consists of the following directories and files:
- `dnsfilter/` - DNS filter implementation
- `upstream/` - Working with DNS upstreams
- `proxy/` - DNS proxy implementation
- `third-party/` - third-party libraries (this is not a subproject, so subproject's rules are not enforced)
- Platform-specific directories (e.g. `ios`, `win`, `mac`, `android`)
- `CMakeLists.txt` - main cmake build config. Should build common things and include 
  platform-specific things.
