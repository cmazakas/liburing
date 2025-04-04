cmake_minimum_required(VERSION 3.30)
project(liburing VERSION 2.10)
include(CTest)

add_subdirectory(src)

set(LIBURING_BUILD_TESTING "${BUILD_TESTING}" CACHE BOOL "Build liburing tests")
if(BUILD_TESTING)
	add_subdirectory(test)
endif()
