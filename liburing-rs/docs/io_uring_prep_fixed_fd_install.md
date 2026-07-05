Prepare fixed file fd installation.
request

# DESCRIPTION

The [io_uring_prep_fixed_fd_install] helper prepares a fixed file
descriptor installation. The submission queue entry *sqe* is setup to
install the direct/fixed file descriptor *fd* with the specified *flags*
file installation flags.

One use case of direct/fixed file descriptors is to turn a regular file
descriptor into a direct one, reducing the overhead of any request that
needs to access this file. This helper provides a way to go the other
way, turning a direct descriptor into a regular file descriptor that can
then subsequently be used by regular system calls that take a normal
file descriptor. This can be handy if no regular file descriptor exists
for this direct descriptor. Either because it was instantiated directly
as a fixed descriptor, or because the regular file was closed with
[close](https://man7.org/linux/man-pages/man2/close.2.html) after being turned into a direct descriptor.

Upon successful return of this request, both a normal and fixed file
descriptor exists for the same file. Either one of them may be used to
access the file. Either one of them may be closed without affecting the
other one.

*flags* may be either zero, or set to **IORING_FIXED_FD_NO_CLOEXEC** to
indicate that the new regular file descriptor should not be closed
during exec. By default, **O_CLOEXEC** will be set on the new descriptor
otherwise. Setting this field to anything but those two values will
result in the request being failed with **-EINVAL** in the CQE *res*
field.

# RETURN VALUE

None

# ERRORS

The CQE *res* field will contain the result of the operation, which in
this case will be the value of the new regular file descriptor. In case
of failure, a negative value is returned.

# SEE ALSO

[io_uring_get_sqe], [io_uring_submit],
[io_uring_register_files], [io_uring_unregister_files],
[io_uring_prep_close_direct], [io_uring_prep_openat_direct]
