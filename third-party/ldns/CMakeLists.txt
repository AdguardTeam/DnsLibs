cmake_minimum_required(VERSION 3.6)
project(ldns)

add_library(ldns EXCLUDE_FROM_ALL
        ldns/packet.c
        ldns/rr.c
        ldns/parse.c
        ldns/buffer.c
        ldns/dname.c
        ldns/util.c
        ldns/dnssec.c
        ldns/dnssec_sign.c
        ldns/dnssec_verify.c
        ldns/dnssec_zone.c
        ldns/keys.c
        ldns/error.c
        ldns/host2str.c
        ldns/str2host.c
        ldns/compat/b64_ntop.c
        ldns/compat/b64_pton.c
        ldns/rdata.c
        ldns/rbtree.c
        ldns/host2wire.c
        ldns/wire2host.c
        ldns/resolver.c
        ldns/rr_functions.c
        ldns/net.c
        ldns/sha1.c
        ldns/sha2.c
        ldns/zone.c)
target_include_directories(ldns PUBLIC ldns)
target_include_directories(ldns PUBLIC posix)
if (WIN32)
    target_link_libraries(ldns wsock32 ws2_32)
    target_sources(ldns PRIVATE ldns/compat/gmtime_r.c)
    set_source_files_properties(ldns/compat/gmtime_r.c PROPERTIES COMPILE_DEFINITIONS HAVE_CONFIG_H=1)
    target_sources(ldns PRIVATE ldns/compat/localtime_r.c)
    set_source_files_properties(ldns/compat/localtime_r.c PROPERTIES COMPILE_DEFINITIONS HAVE_CONFIG_H=1)
endif()
if (NOT APPLE)
    target_sources(ldns PRIVATE ldns/compat/strlcpy.c)
endif ()
