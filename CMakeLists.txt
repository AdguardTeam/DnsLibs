cmake_minimum_required(VERSION 3.6)
project(agdns C CXX)

set(CMAKE_CXX_STANDARD 17)

add_subdirectory(dnsfilter)
add_subdirectory(dnsstamp)
add_subdirectory(upstream)
add_subdirectory(proxy)
