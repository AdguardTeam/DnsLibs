# AGENTS.md — Project Guide for AI Coding Agents

## Project Overview

This is the AdGuard DNS libraries repository, which contains a DNS proxy library that supports all existing DNS protocols including `DNS-over-TLS`, `DNS-over-HTTPS`, `DNSCrypt`, and `DNS-over-QUIC`. The library runs on Linux, macOS, Windows, and Android.

See [README.md](README.md) for full product details.

## Tech Stack

- **C++20** (primary), **C11** — core libraries
- **Kotlin** — Android platform adapter
- **Swift / Objective-C** — Apple platform adapter
- **CMake 3.24+** — build system
- **Conan 2.0.5+** — C++ package manager
- **Ninja** — build backend
- **Clang / LLVM 21+** — compiler and tooling

## Directory Structure

| Directory | Purpose |
| --- | --- |
| `common/` | Shared utilities: event loop, platform abstractions |
| `net/` | Network layer: TLS, sockets, socket factory |
| `proxy/` | Core DNS proxy logic: forwarder, listener, response cache |
| `upstream/` | Upstream DNS implementations: DoH, DoT, DoQ, DNSCrypt, plain DNS |
| `dnsfilter/` | DNS filtering engine: rules, engine, filtering log |
| `dnscrypt/` | DNSCrypt client implementation |
| `dnsstamp/` | DNS stamp parsing |
| `tcpip/` | TCP/IP stack integration |
| `platform/android/` | Android adapter (Kotlin/Gradle) + standalone TUN-based DNS app |
| `platform/mac/` | Apple adapter (Swift/ObjC, CocoaPods, XCFramework) + standalone TUN-based DNS app |
| `platform/windows/` | Windows adapter (C++/CMake, C# bindings) |
| `third-party/` | Vendored dependencies: lwip, pcap_savefile, wintun |
| `scripts/` | Build helpers, Conan export, version increment, git hooks |
| `cmake/` | CMake modules: unit test helper, Conan bootstrapping/provider |
| `bamboo-specs/` | CI/CD pipeline definitions (Bamboo) |

### Module Dependency Flow

```text
common ← net ← upstream ← dnsproxy
common ← dnsfilter ← dnsproxy
common ← dnscrypt ← upstream
common ← dnsstamp ← upstream
common ← tcpip ← dnsproxy (optional, when DNSLIBS_ENABLE_TCPIP=ON)

```

`platform/*` adapters wrap `dnsproxy` for their respective OS.

## Build Commands

Run `make init` once after cloning to set up git hooks.

| Command | What It Does |
| --- | --- |
| `make init` | Configure git hooks path to `./scripts/hooks` |
| `make build_libs` | Bootstrap Conan deps → CMake configure → build `dnsproxy` |
| `make test` | Run all tests (`test-cpp`) |
| `make test-cpp` | Build libs → build test targets → run `ctest` |
| `make lint` | Run all linters (`lint-md` + `lint-cpp`) |
| `make lint-cpp` | `clang-format` check + `clangd-tidy` |
| `make lint-md` | `markdownlint .` |
| `make lint-fix` | Auto-fix all fixable linter issues |
| `make compile_commands` | Generate `compile_commands.json` for IDE integration |
| `make clean` | Clean build artifacts |

Set `BUILD_TYPE=debug` for debug builds (default is `release` →
`RelWithDebInfo`).

## Code Style

### C++

- LLVM-based style, 4-space indent, 120-column limit (see `.clang-format`)
- Pointers and references: `*` and `&` bind to the identifier (right side),
  e.g. `int *ptr`, `const std::string &ref` (LLVM convention)
- Line continuations (wrapped arguments, conditions) indent 8 spaces
- No short functions/blocks on a single line
- Constructor initializers break before comma
- Binary operators break before the operator (non-assignment)
- Extensive static analysis via `.clang-tidy`, all warnings are errors
- Naming conventions (from `.clang-tidy`):
    - `lower_case`: variables, functions, methods, namespaces
    - `CamelCase`: classes, structs, enums, typedefs, template type parameters
    - `UPPER_CASE`: constants, `constexpr` locals, static constants
    - Private/protected members prefixed with `m_`, globals with `g_`
- Use `libc++` (not `libstdc++`)

### Markdown

- Linted with `markdownlint` (config in `.markdownlint.json`)
- Unordered lists use dashes (`-`), indented 4 spaces
- No line-length limit
- **Markdown table formatting (MD060)**: When the Markdownlint MD060 rule
  triggers, switch to tight table formatting with spaces. Example:

  ```markdown
  | Column1 | Column2 |
  | --- | --- |
  | Value 1 | Value 2 |
  ```

  Do NOT use extra padding or alignment characters beyond single spaces.

### General

- Prefer existing patterns over inventing new ones
- Keep changes minimal and focused
- Tests live in `test/` subdirectories alongside the module they cover

## Docker Debug Environment

The `.devcontainer/` directory provides a Docker-based remote debugging setup
(copy `devcontainer.json.example` to `devcontainer.json` to enable it).

- **Image**: Ubuntu 24.04 with clang, cmake, ninja, conan, lldb
- **Purpose**: Remote LLDB debugging, especially for Linux debugging from macOS
- **Start**: `docker-compose -f .devcontainer/docker-compose.yml up -d --build`
- **Build inside**: `docker-compose -f .devcontainer/docker-compose.yml exec dns-libs-debug bash -c "cd /workspace && SKIP_VENV=1 BUILD_TYPE=debug make build_libs"`
- **Debug**: Connect to `lldb-server` on port 12345

## Dependencies

Managed via Conan. Key libraries:

- **native_libs_common** — AdGuard shared library
- **libevent** — async event loop
- **libuv** — async I/O
- **libsodium** — cryptography (DNSCrypt)
- **ldns** — low-level DNS library
- **ngtcp2** — QUIC / DNS-over-QUIC
- **openssl** (BoringSSL) — TLS
- **pcre2** — regex for filtering rules
- **klib** — hash map and other utilities
- **nlohmann_json** — config parsing
- **magic_enum** — enum reflection
- **cxxopts** — CLI argument parsing
- **ada** — URL parser
- **tldregistry** — top-level domain registry for DNS filtering
- **detours** *(Windows only)* — API hooking for system DNS interception

Local conan cache is populated by `make bootstrap_deps` which is dependency for many other make commands.

To find headers for **native_libs_common** (e.g. when resolving symbols or includes), run `make list-deps-dirs` to list Conan package directories, then look in each directory's `include/` subdirectory.

## Mandatory Task Rules

You MUST follow the following rules for EVERY task that you perform:

- You MUST verify it with linter, formatter, and compiler.

  Use the following commands:
    - `make` to check if code builds
    - `make test` to build and run unit tests
    - `make lint` to run the linters
    - `make lint-fix` to fix linting issues that can be fixed automatically
    - `make clang-format` to check the formatting

- You MUST update the unit tests for changed code.

- You MUST run tests with the `make test` script to verify that your changes do
  not break existing functionality.

- When making changes to the project structure, ensure the Project structure
  section in `AGENTS.md` is updated and remains valid.

- If the prompt essentially asks you to refactor or improve existing code, check
  if you can phrase it as a code guideline. If it's possible, add it to
  the relevant Code Guidelines section in `AGENTS.md`.

- After completing the task you MUST verify that the code you've written
  follows the Code Guidelines in this file.
