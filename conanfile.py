from conan import ConanFile
from conan.tools.cmake import CMake, CMakeDeps, CMakeToolchain, cmake_layout
from conan.tools.files import patch, copy
from os.path import join
import re


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
    }
    default_options = {
        "shared": False,
        "fPIC": True,
    }
    # A list of paths to patches. The paths must be relative to the conanfile directory.
    # They are applied in case of the version equals 777 and mostly intended to be used
    # for testing.
    patch_files = []
    exports_sources = patch_files

    def requirements(self):
        self.requires("libevent/2.1.11@adguard_team/native_libs_common", transitive_headers=True)
        self.requires("libsodium/1.0.18@adguard_team/native_libs_common", transitive_headers=True)
        self.requires("libuv/1.41.0@adguard_team/native_libs_common", transitive_headers=True)
        self.requires("klib/2021-04-06@adguard_team/native_libs_common", transitive_headers=True)
        self.requires("ldns/2021-03-29@adguard_team/native_libs_common", transitive_headers=True)
        self.requires("magic_enum/0.9.5", transitive_headers=True)
        self.requires("native_libs_common/6.0.2@adguard_team/native_libs_common", transitive_headers=True)
        self.requires("ngtcp2/1.0.1@adguard_team/native_libs_common", transitive_headers=True)
        self.requires("pcre2/10.37@adguard_team/native_libs_common", transitive_headers=True)
        self.requires("tldregistry/2022-12-26@adguard_team/native_libs_common", transitive_headers=True)
        if "mips" in str(self.settings.arch):
            self.requires("openssl/3.1.5-quic1@adguard_team/native_libs_common", transitive_headers=True, force=True)
        else:
            self.requires("openssl/boring-2023-05-17@adguard_team/native_libs_common", transitive_headers=True)
        self.requires("ada/2.7.4", transitive_headers=True)
        if self.settings.os == "Windows":
            self.requires("detours/2021-04-14@adguard_team/native_libs_common", transitive_headers=True)

    def build_requirements(self):
        self.test_requires("gtest/1.14.0")

    def configure(self):
        self.options["spdlog"].no_exceptions = True
        self.options["gtest"].build_gmock = False
        self.options["pcre2"].build_pcre2grep = False

    def config_options(self):
        if self.settings.os == "Windows":
            del self.options.fPIC

    def source(self):
        self.run(f"git init . && git remote add origin {self.vcs_url} && git fetch")
        if re.match(r'\d+\.\d+\.\d+', self.version) is not None:
            version_hash = self.conan_data["commit_hash"][self.version]["hash"]
            self.run("git checkout -f %s" % version_hash)
        else:
            self.run("git checkout -f %s" % self.version)
            for p in self.patch_files:
                patch(self, patch_file=p)

    def generate(self):
        deps = CMakeDeps(self)
        deps.generate()
        tc = CMakeToolchain(self)
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
        self.cpp_info.libdirs = ['lib']
        self.cpp_info.requires = [
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
