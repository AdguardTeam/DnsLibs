BUILD_TYPE ?= release
ifeq ($(BUILD_TYPE), release)
	CMAKE_BUILD_TYPE = RelWithDebInfo
else
	CMAKE_BUILD_TYPE = Debug
endif
MSVC_VER ?= 17
ifeq ($(origin MSVC_YEAR), undefined)
	ifeq ($(MSVC_VER), 16)
		MSVC_YEAR = 2019
	else ifeq ($(MSVC_VER), 17)
		MSVC_YEAR = 2022
	endif
endif
BUILD_DIR = build
COMPILE_COMMANDS = $(BUILD_DIR)/compile_commands.json
EXPORT_DIR ?= bin
# The exact version of markdownlint-cli2 to run via `npx -y`. Pinning the
# version keeps linting results reproducible across environments.
MARKDOWNLINT_VERSION := 0.23.0
MARKDOWNLINT = npx -y markdownlint-cli2@$(MARKDOWNLINT_VERSION)

ifeq ($(OS), Windows_NT)
NPROC ?= $(or $(NUMBER_OF_PROCESSORS),8)
else
NPROC ?= $(shell (nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 8) | tr -d '\n')
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

# Parallelism level for clangd-tidy. Capped at half the CPU count (not NPROC)
# because each clangd worker can consume hundreds of MB to over 1 GB of RSS;
# running one per CPU can exhaust memory on the CI Linux runner (12 GB / 8
# CPUs), OOM-killing clangd mid-analysis. Override per-invocation, e.g.
# `make clangd-tidy CLANGD_TIDY_JOBS=8`.
CLANGD_TIDY_JOBS ?= $(shell echo $$(( $(NPROC) / 2 > 0 ? $(NPROC) / 2 : 1 )))

# Stream every failing test's captured stdout/stderr into the invoking shell.
# Equivalent to passing --output-on-failure to each ctest invocation, but set
# once here via `export` so it applies to ALL ctest runs in this Makefile
# (test-cpp, test-integration, test-ci) and any future target, without having
# to remember the flag per-call. Without this, failed-test output lands only in
# build/Testing/Temporary/LastTest.log on the runner, which CI may not upload,
# making one-off flakes impossible to diagnose.
export CTEST_OUTPUT_ON_FAILURE=1

# Whether to build with AddressSanitizer. CI enables this on Linux. Maps to
# the -DSANITIZE=yes CMake option (see proxy/CMakeLists.txt), which adds
# -fsanitize=address to the dnsproxy target's compile and link flags.
SANITIZE ?= no
ifeq ($(SANITIZE),yes)
	SANITIZE_FLAGS = -DSANITIZE=yes
else
	SANITIZE_FLAGS =
endif

# Common CMake flags
ifeq ($(OS), Windows_NT)
CMAKE_FLAGS = -DCMAKE_BUILD_TYPE=RelWithDebInfo \
	-DCMAKE_C_COMPILER="cl.exe" \
	-DCMAKE_CXX_COMPILER="cl.exe" \
	-G "Ninja"
else
CMAKE_FLAGS = -DCMAKE_BUILD_TYPE=$(CMAKE_BUILD_TYPE) \
	-DCMAKE_C_COMPILER="clang" \
	-DCMAKE_CXX_COMPILER="clang++" \
	-DCMAKE_CXX_FLAGS="-stdlib=libc++" \
	$(SANITIZE_FLAGS) \
	-GNinja
endif

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
## Setup CMake
## Set SKIP_BOOTSTRAP=1 to skip bootstrapping dependencies
ifeq ($(SKIP_BOOTSTRAP),1)
setup_cmake:
else
setup_cmake: bootstrap_deps
endif
	mkdir -p $(BUILD_DIR) && cmake -S . -B $(BUILD_DIR) $(CMAKE_FLAGS)

.PHONY: compile_commands
## Generate compile_commands.json
compile_commands:
	mkdir -p $(BUILD_DIR) && cmake -S . -B $(BUILD_DIR) \
		$(CMAKE_FLAGS) \
		-DCMAKE_EXPORT_COMPILE_COMMANDS=ON

.PHONY: build_libs
## Build the libraries
build_libs: setup_cmake
	cmake --build $(BUILD_DIR) --target dnsproxy

.PHONY: build_adig
## Build the adig CLI tool
build_adig: setup_cmake
	cmake --build $(BUILD_DIR) --target adig

.PHONY: generate_root_hints
## Regenerate tools/adig/root_servers.h from the IANA root hints.
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
	cmake --build $(BUILD_DIR) --target tests
	ctest --test-dir $(BUILD_DIR) -j $(TEST_JOBS)

## Run the full test suite including real-network integration tests.
## Sets DNSLIBS_INTEGRATION_TESTS=1, so tests that dial public DNS servers
## (DoT/DoH/DoQ/DNSCrypt) are executed instead of skipped. Requires internet.
.PHONY: test-integration
test-integration: build_libs
	cmake --build $(BUILD_DIR) --target tests
	DNSLIBS_INTEGRATION_TESTS=1 ctest --test-dir $(BUILD_DIR) -j $(TEST_JOBS)

# Path to the JUnit XML report written by the CI test target below. The CI
# workflow uploads this file as the test-results artifact.
#
# `ctest --test-dir <build> --output-junit <path>` resolves <path> relative
# to the --test-dir (the build directory), not relative to the current
# working directory. Passing `$(JUNIT_XML)` (= build/junit.xml) as-is would
# therefore write the report to build/build/junit.xml and the CI artifact
# upload at build/junit.xml would find nothing. The ctest invocation below
# passes the absolute path via `$(abspath ...)` to avoid this.
JUNIT_XML ?= $(BUILD_DIR)/junit.xml

## Run the full test suite in the CI configuration, i.e. the way the CI
## builds need it to run:
##   - Real-network integration tests enabled (DNSLIBS_INTEGRATION_TESTS=1),
##     so tests that dial public DNS servers (DoT/DoH/DoQ/DNSCrypt) run
##     instead of being skipped.
##   - JUnit XML report written to $(JUNIT_XML) for the CI test-results
##     artifact upload.
##   - Results submitted to CDash via the ExperimentalTest step.
##
## To reproduce the sanitized Linux CI build, also export
## LDFLAGS=-fuse-ld=lld and ASAN_OPTIONS=detect_container_overflow=0, and
## pass BUILD_TYPE=debug SANITIZE=yes.
##
## TODO(scheduled-builds): Running the real-network integration tests on
## every push and pull request is wasteful and prone to flakes caused by
## transient public-DNS failures. Consider moving this target to a
## scheduled (cron) build and running the offline `make test` target on
## push and pull request events instead.
.PHONY: test-ci
test-ci: build_libs
	cmake --build $(BUILD_DIR) --target tests
	DNSLIBS_INTEGRATION_TESTS=1 ctest --test-dir $(BUILD_DIR) -j $(TEST_JOBS) \
		--output-junit $(abspath $(JUNIT_XML)) \
		-D ExperimentalTest --no-compress-output
