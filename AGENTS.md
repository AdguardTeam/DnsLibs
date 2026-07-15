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
| `common/test_helpers/` | Header-only test utilities: loopback encrypted-protocol responders (`LoopbackDnsServer`, `LoopbackDnscryptServer`, `LoopbackTlsServer`, `LoopbackDohServer`, `LoopbackQuicServer`), `LoopbackHttpConnectProxy`, `MockUpstream`, DNS packet helpers (`dns_test_helpers.h`), `REQUIRE_INTEGRATION()` guard, encrypted-protocol cert kit (`test_certificates.h` + `TestCertificateVerifier` + SPKI/TBS pin helpers) |
| `net/` | Network layer: TLS, sockets, socket factory |
| `proxy/` | Core DNS proxy logic: forwarder, listener, response cache |
| `upstream/` | Upstream DNS implementations: DoH, DoT, DoQ, DNSCrypt, plain DNS |
| `dnsfilter/` | DNS filtering engine: rules, engine, filtering log |
| `dnscrypt/` | DNSCrypt client implementation |
| `dnsstamp/` | DNS stamp parsing |
| `tcpip/` | TCP/IP stack integration |
| `tools/adig/` | `adig`: dig-like DNS query CLI tool (plain DNS, DoT, DoH, DoQ, DNSCrypt) |
| `platform/android/` | Android adapter (Kotlin/Gradle) + standalone TUN-based DNS app |
| `platform/mac/` | Apple adapter (Swift/ObjC, CocoaPods, XCFramework) + standalone TUN-based DNS app |
| `platform/windows/` | Windows adapter (C++/CMake, C# bindings) |
| `third-party/` | Vendored dependencies: lwip, pcap_savefile, wintun |
| `scripts/` | Build helpers, Conan export, version increment, git hooks |
| `cmake/` | CMake modules: unit test helper, Conan bootstrapping/provider |
| `docs/` | Developer and platform-specific documentation |
| `bamboo-specs/` | CI/CD pipeline definitions (Bamboo) |

### Module Dependency Flow

```text
common ← net ← upstream ← dnsproxy
common ← dnsfilter ← dnsproxy
common ← dnscrypt ← upstream
common ← dnsstamp ← upstream
common ← tcpip ← dnsproxy (optional, when DNSLIBS_ENABLE_TCPIP=ON)
common ← upstream ← adig (standalone CLI tool in `tools/adig`)

```

`platform/*` adapters wrap `dnsproxy` for their respective OS.

`tools/adig` is a standalone CLI tool built directly on the `upstream` library.

## Build Commands

Run `make init` once after cloning to set up git hooks.

| Command | What It Does |
| --- | --- |
| `make init` | Configure git hooks path to `./scripts/hooks` |
| `make build_libs` | Bootstrap Conan deps → CMake configure → build `dnsproxy` |
| `make build_adig` | Build the `adig` dig-like DNS query CLI tool |
| `make generate_root_hints` | Regenerate `tools/adig/root_servers.h` from the IANA root hints (needs network) |
| `make test` | Run all tests (`test-cpp`) |
| `make test-cpp` | Build libs → build test targets → run `ctest` |
| `make test-integration` | Build libs → run `ctest` with `DNSLIBS_INTEGRATION_TESTS=1` (real-network tests enabled; requires internet) |
| `make test-ci` | CI target: build libs → build test targets → run `ctest` with `DNSLIBS_INTEGRATION_TESTS=1`, `--output-junit`, and the CDash `ExperimentalTest` step. Pair with `BUILD_TYPE=debug SANITIZE=yes` on Linux to match the sanitized CI build. Note: the real-network integration tests are better suited to a scheduled build (see TODO in `Makefile`) |
| `make lint` | Run all linters (`lint-md` + `lint-cpp`) |
| `make lint-cpp` | `clang-format` check + `clangd-tidy` |
| `make lint-md` | Lint Markdown with `npx -y markdownlint-cli2@0.23.0` |
| `make lint-fix` | Auto-fix all fixable linter issues |
| `make compile_commands` | Generate `compile_commands.json` for IDE integration |
| `make clean` | Clean build artifacts |

Set `BUILD_TYPE=debug` for debug builds (default is `release` →
`RelWithDebInfo`).

## Mandatory Task Rules

You MUST follow the following rules for EVERY task that you perform:

- You MUST verify it with linter, formatter, and compiler.

  Use the following commands:
    - `make` to check if code builds
    - `make test` to build and run unit tests
    - `make lint` to run the linters
    - `make lint-fix` to fix linting issues that can be fixed automatically
    - `make clang-format` to check the formatting
    - `make clang-tidy` to run the `clang-tidy` static analysis

- You MUST prefer running Makefile targets over invoking the underlying
  tools directly. When a Makefile target exists for a task (e.g. build,
  test, lint, format, static analysis), use it rather than calling the
  tool (`clang-format`, `clang-tidy`/`clangd-tidy`, `cmake`, `ctest`,
  `npx markdownlint-cli2`, etc.) by hand. This keeps invocations
  consistent with CI, applies the correct flags and working directory, and
  avoids drift between local and CI behavior.

- You MUST update the unit tests for changed code.

- You MUST run tests with the `make test` script to verify that your changes do
  not break existing functionality.

- When making changes to the project structure, ensure the Project structure
  section in `AGENTS.md` is updated and remains valid.

- You MUST keep documentation in sync with code changes — stale docs are bugs.
  Each `docs/` file maps to a directory (see Directory Structure above); update
  the matching doc when you change that area. Specifically:

    - `DEVELOPMENT.md` — top-level dev workflow (build/test/lint targets,
      manual CMake, `listener_standalone`, Conan export flow). Cross-link to
      `AGENTS.md` / `docs/` instead of duplicating.
    - `docs/adig.md` — `adig` dig-like CLI tool (`tools/adig`): build,
      usage, and options.
    - `docs/architecture.md` — core proxy pipeline, upstream selection,
      `DnsProxySettings` fields/defaults, filtering.
    - `docs/android.md` — `platform/android` build/prereqs/TUN test app.
    - `docs/macos-framework.md` — `AGDnsProxy` XCFramework (`platform/mac`).
    - `docs/macos-testapp.md` — macOS/iOS sample app (`platform/mac/testapp`).
    - `docs/windows-capi.md` — `AdguardDns*` DLL (`platform/windows/capi`).
    - `docs/windows-testapp.md` — Windows C# test app
      (`platform/windows/cs/Adguard.Dns`).
    - `docs/dns-proxy-provider.md` — `NEDNSProxyProvider` integration.

- If the prompt essentially asks you to refactor or improve existing code, check
  if you can phrase it as a code guideline. If it's possible, add it to
  the relevant Code Guidelines section in `AGENTS.md`.

- After completing the task you MUST verify that the code you've written
  follows the Code Guidelines in this file.

## Testing

### Test execution policy

The default `make test` suite MUST run fully offline — no real DNS, no public
internet. This is enforced by the `DNSLIBS_INTEGRATION_TESTS` gate: any test
that dials a real public DNS server (DoT/DoH/DoQ/DNSCrypt against Google,
Cloudflare, Quad9, AdGuard) is wrapped in `REQUIRE_INTEGRATION()` and is
SKIPPED unless `DNSLIBS_INTEGRATION_TESTS=1` is set in the environment.

To run the full integration suite (requires network):

```bash
DNSLIBS_INTEGRATION_TESTS=1 make test
# or, equivalently:
make test-integration
```

Tests must not depend on `sleep()` for correctness — use condition variables,
`coro::to_future(...).get()`, `parallel::all_of`, or explicit filesystem
timestamp manipulation (`utimensat`/`SetFileTime`) instead.

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
- **Never capture in a coroutine lambda; pass everything as a parameter.**
  A lambda coroutine's captures live in the temporary closure object, destroyed
  at the end of the full expression that creates it — before the coroutine
  resumes after its first `co_await`. Any capture read after that is a
  use-after-free. Coroutine parameters, by contrast, are moved/copied into the
  heap-allocated coroutine frame and survive every suspension/resume. This
  applies to `coro::run_detached(...)` and `coro::to_future(...)` wrappers too.

### Markdown

- Linted with `markdownlint-cli2` (config in `.markdownlint-cli2.yaml`),
  run via `npx -y markdownlint-cli2@0.23.0` so no manual install is needed
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
- Prefer in-process loopback servers (`common/test_helpers/loopback_*` +
  `TestCertificateVerifier`) over `REQUIRE_INTEGRATION()` for protocol tests.
  Reserve `REQUIRE_INTEGRATION()` for tests that legitimately exercise a real
  public service (e.g. a one-per-protocol real-world smoke test, or the
  OS-resolver tests). The default `make test` suite MUST remain fully offline.
- Unit tests must not depend on remote/third-party resources (network, DNS, DHCP).
  If an external data set is needed, ship it as a checked-in fixture or generated
  header instead of fetching it at test time.
- When implementing dig-compatible features in `tools/adig`, preserve dig's
  order-sensitive display-flag precedence: options that imply default display
  toggles (e.g. `+trace`) apply those defaults at the point they appear in the
  argv stream, and any later flag (`+comments`, `+stats`, ...) still wins.
  Compare captures of `dig +<option>` against the adig output before
  committing. Keep the per-hop / per-query output filtering in the pure
  `adig_cli` layer (utilities like `format_packet_dig` /
  `format_trace_packet_dig`) so they remain unit-testable without an event
  loop; the coroutine in `adig.cpp` only measures timing and feeds the actual
  server IP / hostname.

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
- **clangd-tidy** — faster clang-tidy replacement (installed from `requirements.txt`)
- **pyyaml** — YAML parsing for `clangd-tidy` config (installed from `requirements.txt`)
- **tqdm** — progress bar for `clangd-tidy` (installed from `requirements.txt`)

Local conan cache is populated by `make bootstrap_deps` which is dependency for many other make commands.
`make bootstrap_deps` and `make clangd-tidy` each create a Python venv from
`requirements.txt` (Python 3.8+) unless `SKIP_VENV=1` is set.

To find headers for **native_libs_common** (e.g. when resolving symbols or includes), run `make list-deps-dirs` to list Conan package directories, then look in each directory's `include/` subdirectory.
