## Coding style

### Language
- We write in C++17

### Naming
- under_score naming for classes, members, functions and variables
- UNDER_SCORE naming for constants, enum constants
- Namespaces:
    - We use `ag` namespace for our classes
    - We use `namespace ... {}` for declarations (usually in headers)
    - Don't use `namespace ... {}` (inc. anonymous namespaces) for definitions (usually in source file)
- Prefixes: 
    - Hungarian notation is prohibited in non-third-party code. 
    - Only allowed prefixes is `_` and `m_`. 
- Suffixes: 
    - No suffixes, even `_t`

### Language features
- Using:
    - Always use `using` instead of `typedef`
    - Both `using` and `using namespace` is allowed, except:
    - `using namespace std;` is forbidden
    - `using namespace` in global scope is forbidden in headers
- Enums:
    - Both `enum` and `enum class` are allowed, depending on desired visibility of constants.
- Trailing return type
    - Use only with templates and only if necessary
- Switch cases:
    - Use `[[fallthrough]]` if switch case should fall through.
    - Don't mix `return` and `break` inside switch: 
      If one switch case ends with `break`, all other should end with `break` or `[[fallthrough]]`.
      If one switch case ends with `return`, all other should end with `return` or `[[fallthrough]]`.
- Comments
    - Should start from capital letter.
    - See "Doxygen comments" for info about Doxygen comments.

### Indentation and style
- K&R style, but:
    - Basic indent - 4 spaces
    - Function body start: same line
    - Constructor body start: next line after member initializers
    - Binary operators like `+`, `-`, etc. should have spaces around them.
    - `if()`, `for()`, `while()`:
        - Use compound statement even if is contains single statement
        - If loop has no body, use compound statement with `// do nothing`
        - Compound statement braces start: same line
        - `else`: same line with compound statement end
    - Namespace content not indented
    - Switch cases are not indented
    - Pointer and reference symbols: space between type and `*` or `&`, 
      no space between identifier and `*` or `&`
    - Line wrapping for conditions:
        ```c++
        //USE THIS INDENTATION INSTEAD
        if ((condition1 && condition2)
                || (condition3 && condition4)
                || !(condition5 && condition6)) {
                doSomethingAboutIt();
        }
        ```

### Header guard
Use non-standard but useful extension `#pragma once`. 
`#ifdef` style guards are not allowed in non-third-party code.

### Doxygen comments
- All public methods and functions should be documented.
- We use Javadoc style with `autobrief` feature.
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
 * @brief Sum of x and y.
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
