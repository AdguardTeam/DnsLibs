from conans import ConanFile, CMake, tools


class LibeventConan(ConanFile):
    name = "libevent"
    version = "2.1.11"
    settings = "os", "compiler", "build_type", "arch"
    options = {"shared": [True, False], "fPIC": [True, False]}
    default_options = {"shared": False, "fPIC": True}
    generators = "cmake"
    requires = ["openssl/boring-2021-05-11@AdguardTeam/DnsLibs"]
    exports_sources = ["CMakeLists.txt", "patches/*"]

    def config_options(self):
        if self.settings.os == "Windows":
            del self.options.fPIC

    def source(self):
        self.run("git clone https://github.com/libevent/libevent.git source_subfolder")
        self.run("cd source_subfolder && git checkout release-2.1.11-stable")
        tools.patch(base_path="source_subfolder", patch_file="patches/bufferevent_patches.patch")
        tools.patch(base_path="source_subfolder", patch_file="patches/evutil_socket_error_to_string_lang.patch")
        tools.patch(base_path="source_subfolder", patch_file="patches/reinit_notifyfds.patch")

    def build(self):
        cmake = CMake(self)
        cmake.definitions["OPENSSL_ROOT_DIR"] = self.deps_cpp_info["openssl"].rootpath
        cmake.definitions["EVENT__LIBRARY_TYPE"]="STATIC"
        cmake.definitions["EVENT__DISABLE_TESTS"]="ON"
        cmake.definitions["EVENT__DISABLE_REGRESS"]="ON"
        cmake.definitions["EVENT__DISABLE_BENCHMARK"]="ON"
        cmake.definitions["EVENT__DISABLE_SAMPLES"]="ON"
        self.run('cmake %s %s || cmake %s %s'
                  % (self.source_folder, cmake.command_line, self.source_folder, cmake.command_line))
        cmake.build()

    def package(self):
        self.copy("*.h", dst="include/event2", src="include/event2")
        self.copy("*.h", dst="include/event2", src="source_subfolder/include/event2")
        self.copy("*.h", dst="include", src="source_subfolder/include")
        self.copy("*.dll", dst="bin", keep_path=False)
        self.copy("*.lib", dst="lib", keep_path=False)
        self.copy("*.so", dst="lib", keep_path=False)
        self.copy("*.dylib", dst="lib", keep_path=False)
        self.copy("*.a", dst="lib", keep_path=False)

    def package_info(self):
        if self.settings.os == "Windows":
            self.cpp_info.libs = ["event", "event_core", "event_extra", "event_openssl"]
        else:
            self.cpp_info.libs = ["event", "event_core", "event_extra", "event_pthreads", "event_openssl"]
