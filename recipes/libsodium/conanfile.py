from conans import ConanFile, CMake, tools


class LibsodiumConan(ConanFile):
    name = "libsodium"
    version = "1.0.18"
    license = "<Put the package license here>"
    author = "<Put your name here> <And your email here>"
    url = "<Package recipe repository url here, for issues about the package>"
    description = "<Description of Libsodium here>"
    topics = ("<Put some tag here>", "<here>", "<and here>")
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
        cmake.configure(build_folder=build_dir)
        cmake.build()
        cmake.install()

#    def package(self):
#        self.copy("*.h", dst="include", src="hello")
#        self.copy("*.lib", dst="lib", keep_path=False)
#        self.copy("*.dll", dst="bin", keep_path=False)
#        self.copy("*.so", dst="lib", keep_path=False)
#        self.copy("*.dylib", dst="lib", keep_path=False)
#        self.copy("*.a", dst="lib", keep_path=False)

    def package_info(self):
        self.cpp_info.libs = ["sodium"]

