# Builds are driven by the CMake presets in CMakePresets.json. The active
# preset is selected from COMPILER (clang/msvc) and BUILD_TYPE (release/debug),
# but PRESET can be set directly to use any preset, e.g.
#   make PRESET=clang-debug-sanitizer test-ci
#   make PRESET=musl-cross-aarch64-relwithdebinfo build_adyg
BUILD_TYPE ?= release

ifeq ($(OS), Windows_NT)
COMPILER ?= msvc
else
COMPILER ?= clang
endif

ifeq ($(BUILD_TYPE), release)
PRESET ?= $(COMPILER)-relwithdebinfo
else
PRESET ?= $(COMPILER)-debug
endif

# Each preset configures into ${sourceDir}/cmake-build-${presetName}. Override
# BUILD_DIR to configure the same preset into several directories, e.g. when
# building one architecture per directory for a macOS universal binary.
BUILD_DIR ?= cmake-build-$(PRESET)
COMPILE_COMMANDS = $(BUILD_DIR)/compile_commands.json

# The exact version of markdownlint-cli2 to run via `npx -y`. Pinning the
# version keeps linting results reproducible across environments.
MARKDOWNLINT_VERSION := 0.23.0
MARKDOWNLINT = npx -y markdownlint-cli2@$(MARKDOWNLINT_VERSION)

ifeq ($(OS), Windows_NT)
NPROC ?= $(or $(NUMBER_OF_PROCESSORS),8)
else
NPROC ?= $(shell (nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 8) | tr -d '\n')
UNAME_S := $(shell uname -s)
endif

# On macOS CMake would otherwise build for whatever architecture the toolchain
# defaults to, so pin it to the host. Override with ARCH, which also takes a
# semicolon-separated list for a universal binary, e.g.
#   make ARCH=x86_64 build_adyg
#   make ARCH='arm64;x86_64' build_adyg
# Not applied to the cross-compiling presets, which don't target Apple.
# 10.15 matches the deployment target of the Apple framework build
# (platform/mac/framework/CMakeLists.txt).
MACOS_DEPLOYMENT_TARGET ?= 10.15
ifeq ($(UNAME_S), Darwin)
ifeq ($(findstring cross,$(PRESET)),)
ARCH ?= $(shell uname -m)
OSX_ARCH_ARGS = -DCMAKE_OSX_ARCHITECTURES="$(ARCH)" \
	-DCMAKE_OSX_DEPLOYMENT_TARGET="$(MACOS_DEPLOYMENT_TARGET)"
endif
endif

# Parallelism level for ctest. Defaults to the number of logical CPUs. Override
# with e.g. `make test TEST_JOBS=1` to force serial execution, or lower it on a
# memory-constrained machine. Tests are parallel-safe: the in-process loopback
# servers (`common/test_helpers/loopback_*`) all bind ephemeral ports, and the
# proxy listener tests configure port 0 so DnsProxy::init() binds an ephemeral
# port and stores the actual port back in the listener settings (read via
# get_settings() after init); the one deliberate-bind-failure test never binds,
# so concurrent test processes never collide on a listener port.
TEST_JOBS ?= $(NPROC)

# Parallelism level for clangd-tidy. Capped at half the CPU count (NPROC / 2,
# not the full NPROC) because each clangd worker can consume hundreds of MB to
# over 1 GB of RSS; running one per CPU can exhaust memory on the CI Linux
# runner (12 GB / 8 CPUs), OOM-killing clangd mid-analysis. Override per-
# invocation, e.g. `make clangd-tidy CLANGD_TIDY_JOBS=8`.
CLANGD_TIDY_JOBS ?= $(shell echo $$(( $(NPROC) / 2 > 0 ? $(NPROC) / 2 : 1 )))

# Stream every failing test's captured stdout/stderr into the invoking shell.
# Equivalent to passing --output-on-failure to each ctest invocation, but set
# once here via `export` so it applies to ALL ctest runs in this Makefile
# (test-cpp, test-integration, test-ci) and any future target, without having
# to remember the flag per-call. Without this, failed-test output lands only in
# $(BUILD_DIR)/Testing/Temporary/LastTest.log on the runner, which CI may not upload,
# making one-off flakes impossible to diagnose.
export CTEST_OUTPUT_ON_FAILURE=1

# Optional compiler launcher (e.g. sccache) for the C and C++ compilers.
# Set on the make command line like `make build_libs CMAKE_LAUNCHER=sccache`
# -- the Linux CI job does this to avoid recompiling the dnsproxy library on
# every push. When non-empty, the matching -DCMAKE_*_COMPILER_LAUNCHER=...
# flags are appended to the configure command line so every cmake configure
# (re)uses the launcher. Empty by default, so local builds are unaffected. The
# Windows CI passes the same flags on its own cmake command line (see
# .github/workflows/build.yml), and cmake/sccache_msvc.cmake (included by the
# root CMakeLists.txt) handles the /Zi->/Z7 switch for MSVC when a launcher is
# set.
CMAKE_LAUNCHER ?=
ifneq ($(CMAKE_LAUNCHER),)
CMAKE_LAUNCHER_FLAGS = -DCMAKE_C_COMPILER_LAUNCHER=$(CMAKE_LAUNCHER) -DCMAKE_CXX_COMPILER_LAUNCHER=$(CMAKE_LAUNCHER)
else
CMAKE_LAUNCHER_FLAGS =
endif

.PHONY: help
## Show this help.
help:
	@awk 'BEGIN {FS = ":"} \
		/^## / {doc = doc substr($$0, 4) " "; next} \
		/^\.PHONY/ {next} \
		/^[a-zA-Z0-9_-]+:/ {if (doc != "") {printf "  \033[36m%-28s\033[0m %s\n", $$1, doc}} \
		{doc = ""}' $(MAKEFILE_LIST)

.PHONY: all
## Build the libraries (default target).
all: build_libs

.PHONY: init
## Initialize the development environment (git hooks, etc.)
init:
	git config core.hooksPath ./scripts/hooks

.PHONY: bootstrap_deps
## Export all the required conan packages to the local cache.
## Skips if all dependencies are already resolved in the local Conan cache.
bootstrap_deps:
	@if conan graph info . --profile:host=default >/dev/null 2>&1; then \
		echo "Conan dependencies already bootstrapped, skipping."; \
	else \
		$(MAKE) do_bootstrap_deps; \
	fi

.PHONY: do_bootstrap_deps
ifeq ($(SKIP_VENV),1)
do_bootstrap_deps:
	./scripts/bootstrap_conan_deps.py
else
do_bootstrap_deps:
	python3 -m venv env && \
	. env/bin/activate && \
	pip install -r requirements.txt && \
	./scripts/bootstrap_conan_deps.py
endif

.PHONY: setup_cmake
## Configure the project with the selected CMake preset (resolves Conan deps).
## Extra CMake flags can be passed via CMAKE_ARGS, e.g.
##   make CMAKE_ARGS=-DDNSLIBS_ENABLE_TCPIP=OFF build_libs
## Set SKIP_BOOTSTRAP=1 to skip bootstrapping dependencies.
## Run `make reconfigure` to apply changed CMAKE_ARGS to a configured tree.
setup_cmake: $(BUILD_DIR)/build.ninja

# The stamp is build.ninja, not CMakeCache.txt: cmake writes the cache before
# the configure step can fail (e.g. in cmake/version.cmake), so keying on the
# cache would leave a half-configured directory that `make` then considers
# ready and `ninja` immediately fails to build. build.ninja appears only on a
# successful configure. Every preset uses the Ninja generator.
#
# Configure only when the build directory has no build file yet. Re-running
# `cmake --preset` over an existing cache breaks the musl cross presets: their
# compiler is a list (`zig;cc;-target;...`), which CMake stores split into
# CMAKE_C_COMPILER plus CMAKE_C_COMPILER_ARG1 and then reports as changed,
# wiping the cache and re-testing `zig` without its arguments. Ninja still
# regenerates by itself when CMakeLists.txt changes.
# bootstrap_deps is order-only: it is phony, and a normal prerequisite would
# make the cache look out of date on every run.
#
# Each preset has its own build directory, so switching build type or
# sanitizer no longer needs the old "wipe the shared build/ dir" dance: the
# CMake-Conan provider's cached absolute paths into
# <build dir>/conan/build/<build type>/generators can never go stale.
ifeq ($(SKIP_BOOTSTRAP),1)
$(BUILD_DIR)/build.ninja:
else
$(BUILD_DIR)/build.ninja: | bootstrap_deps
endif
	cmake --preset $(PRESET) -B $(BUILD_DIR) $(OSX_ARCH_ARGS) $(CMAKE_LAUNCHER_FLAGS) $(CMAKE_ARGS)

.PHONY: reconfigure
## Re-run the CMake configure step from scratch, e.g. after changing CMAKE_ARGS.
reconfigure:
	rm -f $(BUILD_DIR)/CMakeCache.txt $(BUILD_DIR)/build.ninja
	$(MAKE) setup_cmake

.PHONY: compile_commands
## Generate compile_commands.json for IDE / clang-tidy integration.
compile_commands:
	cmake --preset $(PRESET) -B $(BUILD_DIR) $(OSX_ARCH_ARGS) $(CMAKE_LAUNCHER_FLAGS) $(CMAKE_ARGS) \
		-DCMAKE_EXPORT_COMPILE_COMMANDS=ON

.PHONY: build_libs
## Build the libraries
build_libs: setup_cmake
	cmake --build $(BUILD_DIR) --target dnsproxy -j$(NPROC)

.PHONY: build_adyg
## Build the adyg CLI tool
build_adyg: setup_cmake
	cmake --build $(BUILD_DIR) --target adyg -j$(NPROC)

.PHONY: generate_root_hints
## Regenerate tools/adyg/root_servers.h from the IANA root hints.
## Requires network access; ordinary builds/tests use the checked-in header.
generate_root_hints:
	python3 scripts/generate_root_hints.py

.PHONY: clean
## Clean the project
clean:
	cmake --build $(BUILD_DIR) --target clean

.PHONY: lint
lint: lint-md lint-cpp

## Lint c++ files.
.PHONY: lint-cpp
lint-cpp: clang-format clangd-tidy

## Verify that clang-format is version 21 or newer.
.PHONY: check-clang-format-version
check-clang-format-version:
	@if ! command -v clang-format >/dev/null 2>&1; then \
		echo "Error: clang-format is not installed" >&2; exit 1; \
	fi
	@CF_VERSION=$$(clang-format --version | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1); \
	CF_MAJOR=$$(echo "$$CF_VERSION" | cut -d. -f1); \
	if [ "$$CF_MAJOR" -lt 21 ] 2>/dev/null; then \
		echo "Error: clang-format version 21 or newer is required, found $$CF_VERSION" >&2; exit 1; \
	fi

## Check c++ code formatting with clang-format.
.PHONY: clang-format
clang-format: check-clang-format-version
	git ls-files --exclude-standard -- . ":!third-party/**" ":!**/pigeon/**" \
		| grep -E '\.(cpp|c|h)$$' \
		| xargs clang-format -n -Werror

## Check c++ code formatting with clang-tidy.
.PHONY: clang-tidy
clang-tidy: compile_commands
	run-clang-tidy -p $(BUILD_DIR) -config-file='.clang-tidy' '^(?!.*(/third-party/)).*\.cpp$$'

## Check c++ code formatting with clangd-tidy.
.PHONY: clangd-tidy
clangd-tidy: compile_commands
ifeq ($(SKIP_VENV),1)
	jq -r '.[] | select(.file | endswith(".cpp")) | .file' $(COMPILE_COMMANDS) \
		| grep -vE '(^|/)(third-party)(/|$$)' \
		| sort -u \
		| xargs clangd-tidy -p $(BUILD_DIR) --tqdm -j$(CLANGD_TIDY_JOBS)
else
	python3 -m venv env && \
	. env/bin/activate && \
	pip install -r requirements.txt && \
	jq -r '.[] | select(.file | endswith(".cpp")) | .file' $(COMPILE_COMMANDS) \
		| grep -vE '(^|/)(third-party)(/|$$)' \
		| sort -u \
		| xargs clangd-tidy -p $(BUILD_DIR) --tqdm -j$(CLANGD_TIDY_JOBS)
endif

## Lint markdown files.
## `markdownlint-cli2` is run via `npx -y`, so it does not need to be
## installed beforehand. Only Node.js/npm must be available on the system.
## The exact version is pinned via `MARKDOWNLINT_VERSION` above.
.PHONY: lint-md
lint-md:
	$(MARKDOWNLINT) "**/*.md"

## Fix linter issues that are auto-fixable.
.PHONY: lint-fix
lint-fix: lint-fix-md lint-fix-cpp

## Auto-fix c++ formatting with clang-format.
.PHONY: lint-fix-cpp
lint-fix-cpp: check-clang-format-version
	git ls-files --exclude-standard -- . ":!third-party/**" ":!**/pigeon/**" \
		| grep -E '\.(cpp|c|h)$$' \
		| xargs clang-format -i

## Auto-fix markdown files.
.PHONY: lint-fix-md
lint-fix-md:
	$(MARKDOWNLINT) --fix "**/*.md"

## List Conan dependency package directories.
.PHONY: list-deps-dirs
list-deps-dirs: compile_commands
	@GENERATORS_DIR=$$(cmake -L $(BUILD_DIR) 2>/dev/null \
		| grep '_DIR:PATH=' \
		| grep -v 'NOTFOUND' \
		| head -1 \
		| sed 's/.*:PATH=//') && \
	grep -h '_PACKAGE_FOLDER_' "$$GENERATORS_DIR"/* 2>/dev/null \
		| sed -n 's/set(\(.*\)_PACKAGE_FOLDER_[A-Z_]* "\([^"]*\)").*/\1 \2/p' \
		| sort -u

.PHONY: test
test: test-cpp

.PHONY: test-cpp
test-cpp: build_libs
	cmake --build $(BUILD_DIR) --target tests -j$(NPROC)
	ctest --test-dir $(BUILD_DIR) -j $(TEST_JOBS)

## Run the full test suite including real-network integration tests.
## Sets DNSLIBS_INTEGRATION_TESTS=1, so tests that dial public DNS servers
## (DoT/DoH/DoQ/DNSCrypt) are executed instead of skipped. Requires internet.
.PHONY: test-integration
test-integration: build_libs
	cmake --build $(BUILD_DIR) --target tests -j$(NPROC)
	DNSLIBS_INTEGRATION_TESTS=1 ctest --test-dir $(BUILD_DIR) -j $(TEST_JOBS)

# Name of the JUnit XML report written by the CI test target below; the CI
# workflow uploads $(BUILD_DIR)/$(JUNIT_XML) as the test-results artifact.
# `ctest --test-dir <build> --output-junit <path>` resolves <path> relative to
# the --test-dir (the build directory), so this is a bare file name.
JUNIT_XML ?= junit.xml

## Run the full test suite in the CI configuration, i.e. the way the CI
## builds need it to run:
##   - Real-network integration tests enabled (DNSLIBS_INTEGRATION_TESTS=1),
##     so tests that dial public DNS servers (DoT/DoH/DoQ/DNSCrypt) run
##     instead of being skipped.
##   - JUnit XML report written to $(BUILD_DIR)/$(JUNIT_XML) for the CI
##     test-results artifact upload.
##   - Results submitted to CDash via the ExperimentalTest step.
##
## To reproduce the sanitized Linux CI build, also export
## LDFLAGS=-fuse-ld=lld and ASAN_OPTIONS=detect_container_overflow=0, and
## pass PRESET=clang-debug-sanitizer.
##
## TODO(scheduled-builds): Running the real-network integration tests on
## every push and pull request is wasteful and prone to flakes caused by
## transient public-DNS failures. Consider moving this target to a
## scheduled (cron) build and running the offline `make test` target on
## push and pull request events instead.
.PHONY: test-ci
test-ci: build_libs
	cmake --build $(BUILD_DIR) --target tests -j$(NPROC)
	DNSLIBS_INTEGRATION_TESTS=1 ctest --test-dir $(BUILD_DIR) -j $(TEST_JOBS) \
		--output-junit $(JUNIT_XML) \
		-D ExperimentalTest --no-compress-output
