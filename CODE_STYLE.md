## Coding style

### Language
- We write in C++17

### Naming
- under_score naming for classes, members, functions and variables
- UNDER_SCORE naming for constants, enum constants
- Namespaces:
    - Use `ag` namespace for our classes.
    - Use `namespace ... {}` for declarations (usually in headers).
    - Don't use `namespace ... {}` (inc. anonymous namespaces) for definitions (usually in source file).
- Prefixes: 
    - Hungarian notation is prohibited in non-third-party code.
    - Only allowed prefixes is `_` and `m_`. 
- Suffixes: 
    - No suffixes, even `_t`

### Language features
- Using:
    - Always use `using` instead of `typedef`.
    - Both `using` and `using namespace` is allowed, except:
    - `using namespace std;` is forbidden.
    - `using namespace` in global scope is forbidden in headers.
- Enums:
    - Both `enum` and `enum class` are allowed, depending on desired visibility of constants.
- Trailing return type:
    - Use only with templates and only if necessary.
- Switch cases:
    - Use `[[fallthrough]]` if switch case contains one or more statements and should fall through to the next switch case.
- Comments:
    - Should start from capital letter.
    - See "Doxygen comments" for info about Doxygen comments.
- Exceptions:
    - C++ exceptions should not be used.

### Indentation and style
- K&R style, but:
    - Basic indent - 4 spaces. Tabs are not allowed.
    - UTF-8 encoding, `\n` line endings.
    - Function body start: same line.
    - Constructor body start: next line after member initializers.
    - Binary operators like `+`, `-`, etc. should have spaces around them.
    - `if()`, `for()`, `while()`:
        - Use compound statement even if is contains single statement.
        - If loop has no body, use compound statement with `// do nothing`.
        - Compound statement braces start: same line.
        - `else`: same line with compound statement end.
    - Namespace content not indented.
    - Switch cases are not indented.
    - Pointer and reference symbols: space between type and `*` or `&`, 
      no space between identifier and `*` or `&`.
    - Line wrapping for conditions:
        ```c++
        if ((condition1 && condition2)
                || (condition3 && condition4)
                || !(condition5 && condition6)) {
            do_something_about_it();
        }
        ```

### Header guard
Use non-standard but useful extension `#pragma once`. 
`#ifdef` style guards are not allowed in non-third-party code.

### Doxygen comments
- All public methods and functions should be documented.
- Use Javadoc style with `autobrief` feature.
- `autobrief` means that first statement of long description is automatically become brief description.
  So `@brief` is redundant.
- Use `@return`, not `@returns`
- Use `[out]` in `@param` only if code is not explanatory.
- Don't use `[in]` in `@param`.
- Don't use extra line endings.
- Use infinitive instead of third person in brief descriptions.
- Descriptions should start from capital letter.

Examples:
```
/**
 * Sum of x and y.
 * This function is usually used to get sum of x and y.
 * @param x The x
 * @param yy The y
 * @return Sum of x and y.
int plus(int x, int yy) {
    return x + yy;
}
enum class t {
    A, /**< One-line post-identifier comment */
    /** Another one-line comment */
    B,
    /** Third one-line comment */
    C,
    D, /**< One-line post-identifier comment */
}
```

### Logging
    - Log messages should start from capital letter.
    - Use WARN/ERROR level only for internal logic warnings/errors and network errors that make library unusable.
    - Use INFO level for messages of regular proxy operation that regular users will see in their log.
    - Use DEBUG level for messages that will be logged only with debug logging on.
      This includes non-fatal network errors, malformed responses, etc. Why network-related errors are usually
      "DEBUG" level? These errors are part of regular operation of network client,
      so they reported in reply to client of library.
    - Use TRACE debug level for trace messages.
    
### Code sample
type.h
```c++
namespace ag {

struct type {
    int x;
    type();
    std::string *func(const std::string &param);
}

} // namespace ag
```
type.cc
```c++
static constexpr auto FIVE = 5;

ag::type() : x(0)
{
}

std::string *ag::func(const std::string &param) {
    if (time(nullptr) % 2 == 0) {
        return new std::string(param);
    } else {
        std::string *ret = nullptr;
        for (int i = x; i < 10; i++) {
            switch (i) {
            case FIVE:
                ret = new std::string(std::to_string(FIVE) + ", not " + param);
                break;
            default:
                std::clog << "not " << FIVE << std::endl;
                break;
            }
        }
        return ret;
    }
}
```
