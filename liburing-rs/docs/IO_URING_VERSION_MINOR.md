Functions and macros to check the liburing
version

# DESCRIPTION

The [io_uring_check_version] function returns *false* if the
liburing library loaded by the dynamic linker is greater-than or
equal-to the *major* and *minor* numbers provided.

The [IO_URING_CHECK_VERSION](https://man7.org/linux/man-pages/man2/IO_URING_CHECK_VERSION.2.html) macro returns *0* if the liburing
library being compiled against is greater-than or equal-to the *major*
and *minor* numbers provided.

The [io_uring_major_version] function returns the *major* version
number of the liburing library loaded by the dynamic linker.

The [IO_URING_VERSION_MAJOR](https://man7.org/linux/man-pages/man2/IO_URING_VERSION_MAJOR.2.html) macro returns the *major* version
number of the liburing library being compiled against.

The [io_uring_minor_version] function returns the *minor* version
number of the liburing library loaded by the dynamic linker.

The [IO_URING_VERSION_MINOR](https://man7.org/linux/man-pages/man2/IO_URING_VERSION_MINOR.2.html) macro returns the *minor* version
number of the liburing library being compiled against.
