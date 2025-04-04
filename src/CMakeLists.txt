add_library(liburing_obj OBJECT setup.c queue.c register.c syscall.c version.c)

target_include_directories(
	liburing_obj
	PUBLIC
	$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)

target_compile_features(liburing_obj PUBLIC c_std_11)

target_compile_definitions(liburing_obj PUBLIC -D_GNU_SOURCE -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64 -DLIBURING_INTERNAL)
target_compile_options(liburing_obj PUBLIC "-Wall;-Wextra;-fno-stack-protector;-Wno-unused-parameter")
target_link_options(liburing_obj PUBLIC "-Wl,-z,defs")

set(LIBURING_CONFIG_NOLIBC OFF CACHE BOOL "Toggle nolibc mode")
if(LIBURING_CONFIG_NOLIBC)
	target_sources(liburing_obj PUBLIC nolibc.c)
	target_compile_options(liburing_obj PUBLIC "-nostdlib;-nodefaultlibs;-ffreestanding;-fno-builtin;-fno-stack-protector")
	target_link_options(liburing_obj PUBLIC "-nostdlib;-nodefaultlibs")
	target_compile_definitions(liburing_obj PUBLIC CONFIG_NOLIBC)
endif()

set(LIBURING_CONFIG_USE_SANITIZER OFF CACHE BOOL "Build liburing with asan instrumentation")
if(LIBURING_CONFIG_USE_SANITIZER)
	target_sources(liburing_obj PUBLIC sanitize.c)
	target_compile_options(liburing_obj PUBLIC "-fsanitize=address,undefined;-g;-fno-omit-frame-pointer;-fno-optimize-sibling-calls")
	target_link_options(liburing_obj PUBLIC "-fsanitize=address,undefined")
	target_compile_definitions(liburing_obj PUBLIC CONFIG_USE_SANITIZER)
endif()


add_library(liburing $<TARGET_OBJECTS:liburing_obj>)
set_target_properties(liburing PROPERTIES PREFIX "")

add_library(liburing-ffi ffi.c)
target_link_libraries(liburing-ffi PRIVATE liburing_obj)
set_target_properties(liburing-ffi PROPERTIES PREFIX "")
