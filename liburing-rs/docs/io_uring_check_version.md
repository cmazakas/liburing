Functions and macros to check the liburing version.

# DESCRIPTION

The **io_uring_check_version**(3) function returns *false* if the
liburing library loaded by the dynamic linker is greater-than or
equal-to the *major* and *minor* numbers provided.

The **io_uring_major_version**(3) function returns the *major* version
number of the liburing library loaded by the dynamic linker.

The **io_uring_minor_version**(3) function returns the *minor* version
number of the liburing library loaded by the dynamic linker.
