from conans import ConanFile, CMake, tools


class LdnsConan(ConanFile):
    name = "ldns"
    version = "2021-03-29"
    settings = "os", "compiler", "build_type", "arch"
    options = {"shared": [True, False], "fPIC": [True, False]}
    default_options = {"shared": False, "fPIC": True}
    generators = "cmake"
    requires = ["libevent/2.1.11", "spdlog/1.8.5"]
    exports_sources = ["compat/*", "windows/*", "*.patch", "CMakeLists.txt"]

    def config_options(self):
        if self.settings.os == "Windows":
            del self.options.fPIC

    def source(self):
        self.run("git clone https://github.com/NLnetLabs/ldns.git")
        self.run("cd ldns && git checkout 7128ef56649e0737f236bc5d5d640de38ff0036d")
        tools.patch(base_path="ldns", patch_file="windows.patch")

    def build(self):
        cmake = CMake(self)
        cmake.configure()
        cmake.build()

    def package(self):
        self.copy("*.h", dst="include/ldns", src="ldns/ldns")
        self.copy("*.h", dst="include/ldns", src="compat/ldns")
        self.copy("*.lib", dst="lib", keep_path=False)
        self.copy("*.dll", dst="bin", keep_path=False)
        self.copy("*.so", dst="lib", keep_path=False)
        self.copy("*.dylib", dst="lib", keep_path=False)
        self.copy("*.a", dst="lib", keep_path=False)

    def package_info(self):
        self.cpp_info.libs = ["ldns"]
