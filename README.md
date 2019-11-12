# AdGuard C++ DNS libraries

## After checkout

```
git submodule init
git submodule update
```

## Build instructions

TODO

## Code rules 

- use already written third-party libraries (Google Test for tests, etc.)
- use submodules
- use CMake

### Coding style

- C++17
- under_score naming for classes, members, functions and variables
- UNDER_SCORE naming for constants, enums
- Namespaces:
    - Use `ag` namespace for our classes
    - Use `namespace ... {}` for declarations
    - Don't use `namespace ... {}` for definitions
- Using:
    - Always use `using` instead of `typedef`
    - Both `using` and `using namespace` is allowed, except:
    - `using namespace std;` is forbidden 
- Prefixes: 
    - Hungarian notation is prohibited in non-third-party code. 
    - Only allowed prefixes is `_` and `m_`. 
- Suffixes: 
    - No suffixes, even `_t`
- Indentation and style - K&R style, but:
    - Basic indent - 4 spaces
    - Method/Function body start: same line
    - Constructor body start: next line after member initializers
    - `if()`, `for()`:
        - Use braces even for single statement in this cases
        - Braces start: same line
        - Braces end: same line for `else`
    - Namespace content not indented
    - Switch cases are not indented
    - Pointer and reference symbols: space between type and `*` or `&`
- Enums:
    - Both `enum` and `enum class` are allowed, depending on desired visibility of constants.
- Trailing return type
    - Use only with templates
    
Code sample:
```c++
namespace ag {
    struct type {
        int x;
        type();
        std::string *func(const std::string &param);
    }
} // namespace ag

constexpr auto FIVE = 5;

ag::type() : x(0)
{
}

std::string *ag::func(const std::string &param) {
    if (time(nullptr) % 2 == 0) {
        return new std::string(param);
    } else {
        for (int i = x; i < 10; i++) {
            switch (i) {
            case FIVE:
                return new std::string(std::to_string(FIVE) + ", not " + param);
            default:
                std::clog << "not " << FIVE << " yet" << std::endl;
            }
        }
    }
}
```

## Project structure

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

## License

Copyright (C) AdGuard Software Ltd.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
