cmake_minimum_required(VERSION 3.6)
project(agdns C CXX)

add_subdirectory(dnsfilter)
add_subdirectory(tls)
add_subdirectory(upstream)
add_subdirectory(proxy)
enable_testing()
