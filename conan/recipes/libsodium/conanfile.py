from conans import ConanFile, CMake, tools


class LibsodiumConan(ConanFile):
    name = "libsodium"
    version = "1.0.18"
    settings = "os", "compiler", "build_type", "arch"
    options = {"shared": [True, False], "fPIC": [True, False]}
    default_options = {"shared": False, "fPIC": True}
    generators = "cmake"
    exports_sources = ["CMakeLists.txt", "sodiumConfig.cmake.in"]

    def config_options(self):
        if self.settings.os == "Windows":
            del self.options.fPIC

    def source(self):
        self.run("git clone https://github.com/jedisct1/libsodium.git libsodium")
        self.run("cd libsodium && git checkout 1.0.18")

    def build(self):
        cmake = CMake(self)
        build_dir = "%s/build" % self.source_folder
        cmake.definitions["BUILD_SHARED_LIBS"]="OFF"
        cmake.configure(build_folder=build_dir)
        cmake.build()
        cmake.install()

    def package_info(self):
        if self.settings.os == "Windows":
            self.cpp_info.libs = ["libsodium"]
        else:
            self.cpp_info.libs = ["sodium"]

        self.cpp_info.defines.append("SODIUM_STATIC=1")
