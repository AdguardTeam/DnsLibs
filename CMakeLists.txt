cmake_minimum_required(VERSION 3.12)
project(agdns C CXX)

add_subdirectory(dnsfilter)
add_subdirectory(net)
add_subdirectory(upstream)
add_subdirectory(proxy)

enable_testing()
