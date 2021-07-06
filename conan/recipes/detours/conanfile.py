from conans import ConanFile, CMake, tools


class DetoursConan(ConanFile):
    name = "detours"
    version = "2021-04-14"
    settings = "os", "compiler", "build_type", "arch"
    options = {"shared": [True, False], "fPIC": [True, False]}
    default_options = {"shared": False, "fPIC": True}
    generators = "cmake"

    def config_options(self):
        if self.settings.os == "Windows":
            del self.options.fPIC

    def source(self):
        self.run("git clone https://github.com/microsoft/Detours source_subfolder")
        self.run("cd source_subfolder && git checkout fe7216c037c898b1f65330eda85e6146b6e3cb85")

    def build(self):
        self.run("cd source_subfolder\\src && set CC=cl && set CXX=cl && nmake")

    def package(self):
        self.copy("*.h", dst="include", src="source_subfolder/include")
        self.copy("*detours.lib", dst="lib", keep_path=False)
        self.copy("*detours.pdb", dst="lib", keep_path=False)

    def package_info(self):
        self.cpp_info.libs = ["detours"]
