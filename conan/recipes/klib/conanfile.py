from conans import ConanFile, CMake, tools


class KlibConan(ConanFile):
    name = "klib"
    version = "2021-04-06"
    settings = "os", "compiler", "build_type", "arch"
    options = {"shared": [True, False], "fPIC": [True, False]}
    default_options = {"shared": False, "fPIC": True}
    generators = "cmake"

    def config_options(self):
        if self.settings.os == "Windows":
            del self.options.fPIC

    def source(self):
        self.run("git clone https://github.com/attractivechaos/klib")
        self.run("cd klib && git checkout e1b2a40de8e2a46c05cc5dac9c6e5e8d15ae722c")

    def package(self):
        self.copy("khash.h", dst="include", src="klib")
        self.copy("kvec.h", dst="include", src="klib")
