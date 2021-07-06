from conans import ConanFile, CMake, tools


class Ngtcp2Conan(ConanFile):
    name = "ngtcp2"
    version = "2021-05-13"
    settings = "os", "compiler", "build_type", "arch"
    options = {"shared": [True, False], "fPIC": [True, False]}
    default_options = {"shared": False, "fPIC": True}
    generators = "cmake"
    requires = ["openssl/boring-2021-05-11@AdguardTeam/DnsLibs"]
    exports_sources = ["CMakeLists.txt"]

    def config_options(self):
        if self.settings.os == "Windows":
            del self.options.fPIC

    def source(self):
        self.run("git clone https://github.com/ngtcp2/ngtcp2.git source_subfolder")
        self.run("cd source_subfolder && git checkout d9524643af810c2b51f05fb36c500abf13fd9116")

    def build(self):
        cmake = CMake(self)
        cmake.definitions["BUILD_SHARED_LIBS"]="OFF"
        cmake.definitions["ENABLE_OPENSSL"]="OFF"
        cmake.definitions["ENABLE_BORINGSSL"]="ON"
        cmake.definitions["HAVE_SSL_IS_QUIC"]="ON"
        cmake.definitions["HAVE_SSL_SET_QUIC_EARLY_DATA_CONTEXT"]="ON"
        cmake.configure()
        cmake.build()

        # Explicit way:
        # self.run('cmake %s/hello %s'
        #          % (self.source_folder, cmake.command_line))
        # self.run("cmake --build . %s" % cmake.build_config)

    def package(self):
        self.copy("*.h", dst="include", src="source_subfolder/lib/includes")
        self.copy("*.h", dst="include", src="source_subfolder/crypto/includes")
        self.copy("*.lib", dst="lib", keep_path=False)
        self.copy("*.dll", dst="bin", keep_path=False)
        self.copy("*.so", dst="lib", keep_path=False)
        self.copy("*.dylib", dst="lib", keep_path=False)
        self.copy("*.a", dst="lib", keep_path=False)

    def package_info(self):
        self.cpp_info.libs = ["ngtcp2", "ngtcp2_crypto_boringssl"]
        self.cpp_info.defines.append("NGTCP2_STATICLIB=1")
