from conan import ConanFile
from conan.tools.cmake import CMake, CMakeDeps, CMakeToolchain, cmake_layout
from conan.tools.files import patch, copy, update_conandata
from conan.tools.scm import Git
from os.path import join
import re, os, shutil


class DnsLibsConan(ConanFile):
    name = "dns-libs"
    license = "Apache-2.0"
    author = "AdguardTeam"
    url = "https://github.com/AdguardTeam/DnsLibs"
    vcs_url = "https://github.com/AdguardTeam/DnsLibs.git"
    description = "A DNS proxy library that supports all existing DNS protocols"
    topics = ("dns", "proxy", "security", "adblock", "privacy")
    settings = "os", "compiler", "build_type", "arch"
    options = {
        "shared": [True, False],
        "fPIC": [True, False],
        "tcpip": [True, False],
    }
    default_options = {
        "shared": False,
        "fPIC": True,
        "tcpip": True,
    }
    # A list of paths to patches. The paths must be relative to the conanfile directory.
    # They are applied in case of the version equals 777 and mostly intended to be used
    # for testing.
    patch_files = []
    exports_sources = patch_files

    def requirements(self):
        self.requires("cxxopts/3.1.1", transitive_headers=True)
        self.requires("libevent/2.1.11@adguard/oss", transitive_headers=True)
        self.requires("libsodium/1.0.18@adguard/oss", transitive_headers=True)
        self.requires("libuv/1.41.0@adguard/oss", transitive_headers=True)
        self.requires("klib/2021-04-06@adguard/oss", transitive_headers=True)
        self.requires("ldns/2021-03-29@adguard/oss", transitive_headers=True)
        self.requires("magic_enum/0.9.5", transitive_headers=True)
        self.requires("native_libs_common/8.1.42@adguard/oss", transitive_headers=True)
        self.requires("ngtcp2/1.22.1@adguard/oss", transitive_headers=True)
        self.requires("pcre2/10.37@adguard/oss", transitive_headers=True)
        self.requires("tldregistry/2022-12-26@adguard/oss", transitive_headers=True)
        if "mips" in str(self.settings.arch):
            self.requires("openssl/3.1.5-quic1@adguard/oss", transitive_headers=True, force=True)
        else:
            self.requires("openssl/boring-2024-09-13@adguard/oss", transitive_headers=True)
        self.requires("ada/2.7.4", transitive_headers=True)
        if self.settings.os == "Windows":
            self.requires("detours/2021-04-14@adguard/oss", transitive_headers=True)
            self.requires("nlohmann_json/3.12.0")

    def build_requirements(self):
        self.test_requires("gtest/1.14.0")

    def configure(self):
        self.options["spdlog"].no_exceptions = True
        self.options["gtest"].build_gmock = False
        self.options["pcre2"].build_pcre2grep = False

    def config_options(self):
        if self.settings.os == "Windows":
            del self.options.fPIC

    def export(self):
        # The exported sources carry no .git, so the build's git describe would
        # fall back to 0.0.0-git for "local" exports. Capture the describe version
        # now (the recipe folder still has .git) into conandata.yml for generate()
        # to feed back into cmake/version.cmake.
        if self.version == "local":
            described = self._git_described_version(Git(self))
            if described:
                update_conandata(self, {"local_version": described})

    def export_sources(self):
        if self.version == "local":
            git = Git(self)
            included = git.included_files()
            for i in included:
                dst = os.path.join(self.export_sources_folder, i)
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                shutil.copy2(i, dst)

    @staticmethod
    def _git_described_version(git):
        # Quote the glob: Git.run executes through a shell, so an unquoted "v*"
        # would expand against files in the recipe dir and match no tags.
        try:
            described = git.run('describe --tags --match "v*"').strip()
        except Exception:
            return ""
        return described[1:] if described.startswith("v") else described

    def source(self):
        if os.listdir(self.source_folder):
            return

        git = Git(self)
        version = str(self.version)
        # A "git describe" snapshot version looks like "<tag>-<n>-g<rev>"; check
        # out the commit after "-g". A plain release version is the "v<version>"
        # tag. fetch_commit can't fetch an abbreviated rev (GitHub rejects it),
        # so snapshots clone the repo and check the commit out locally.
        described = re.search(r"-g([0-9a-f]+)$", version)
        if described:
            git.clone(url=self.vcs_url, target=".")
            git.checkout(described.group(1))
        else:
            git.fetch_commit(self.vcs_url, f"v{version}")

    def generate(self):
        deps = CMakeDeps(self)
        deps.generate()
        tc = CMakeToolchain(self)
        tc.cache_variables["DNSLIBS_ENABLE_TCPIP"] = self.info.options.tcpip
        # Drive cmake/version.cmake from the package version so the conan source
        # (fetched by tag, no .git for git describe) bakes the right version into
        # the generated version.h. For "local" exports the describe version was
        # stapled into conandata.yml at export time.
        version = str(self.version)
        if version == "local":
            version = (self.conan_data or {}).get("local_version") or version
        if version and version != "local":
            tc.cache_variables["DNS_LIBS_VERSION"] = version
        tc.generate()

    def layout(self):
        cmake_layout(self)

    def build(self):
        cmake = CMake(self)
        cmake.configure()
        cmake.build(target="dnsproxy")

    def package(self):
        MODULES = [
            "common",
            "dnscrypt",
            "dnsfilter",
            "dnsstamp",
            "net",
            "proxy",
            "upstream",
        ]

        for m in MODULES:
            copy(self, "*.h", src=join(self.source_folder, "%s/include" % m), dst=join(self.package_folder, "include"), keep_path = True)

        # version.h is generated (the source ships only version.h.in,
        # which the *.h glob above does not match); ship the baked copy.
        copy(self, "dns/common/version.h", src=join(self.build_folder, "common/gen"), dst=join(self.package_folder, "include"), keep_path=True)

        copy(self, "*.dll", src=self.build_folder, dst=join(self.package_folder, "bin"), keep_path=False)
        copy(self, "*.lib", src=self.build_folder, dst=join(self.package_folder, "lib"), keep_path=False)
        copy(self, "*.so", src=self.build_folder, dst=join(self.package_folder, "lib"), keep_path=False)
        copy(self, "*.dylib", src=self.build_folder, dst=join(self.package_folder, "lib"), keep_path=False)
        copy(self, "*.a", src=self.build_folder, dst=join(self.package_folder, "lib"), keep_path=False)


    def package_info(self):
        self.cpp_info.name = "dns-libs"
        self.cpp_info.includedirs = ["include"]
        self.cpp_info.libs = [
            "dnsproxy",
            "dnsfilter",
            "upstream",
            "dnscrypt",
            "dnsstamp",
            "dnslibs_net",
            "dnslibs_common",
        ]
        if self.options.tcpip:
            self.cpp_info.libs.append("dnslibs_tcpip")
        self.cpp_info.libdirs = ['lib']
        self.cpp_info.requires = [
            "cxxopts::cxxopts",
            "magic_enum::magic_enum",
            "pcre2::pcre2",
            "libsodium::libsodium",
            "libevent::libevent",
            "libuv::libuv",
            "klib::klib",
            "ldns::ldns",
            "ngtcp2::ngtcp2",
            "native_libs_common::native_libs_common",
            "tldregistry::tldregistry",
            "openssl::openssl",
            "ada::ada",
        ]
        if self.settings.os == "Windows":
            self.cpp_info.requires.append("detours::detours")
            self.cpp_info.requires.append("nlohmann_json::nlohmann_json")
