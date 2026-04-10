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

ifeq ($(OS), Windows_NT)
NPROC ?= $(or $(NUMBER_OF_PROCESSORS),8)
else
NPROC ?= $(shell (nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 8) | tr -d '\n')
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
		| xargs clangd-tidy -p $(BUILD_DIR) --tqdm -j$(NPROC)
else
	python3 -m venv env && \
	. env/bin/activate && \
	pip install -r requirements.txt && \
	jq -r '.[] | select(.file | endswith(".cpp")) | .file' $(COMPILE_COMMANDS) \
		| grep -vE '(^|/)(third-party)(/|$$)' \
		| sort -u \
		| xargs clangd-tidy -p $(BUILD_DIR) --tqdm -j$(NPROC)
endif

## Lint markdown files.
## `markdownlint-cli` should be installed:
##    macOS: `brew install markdownlint-cli`
##    Linux: `npm install -g markdownlint-cli`
.PHONY: lint-md
lint-md:
	echo markdownlint version:
	markdownlint --version
	markdownlint .

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
	markdownlint --fix .

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
	ctest --test-dir $(BUILD_DIR)