Prepare a fadvise request.

# DESCRIPTION

The [io_uring_prep_fadvise] function prepares an fadvise request.
The submission queue entry *sqe* is setup to use the file descriptor
pointed to by *fd* to start an fadvise operation at *offset* and of
*len* length in bytes, giving it the advise located in *advice*.

The [io_uring_prep_fadvise64] function works like
[io_uring_prep_fadvise] except that it takes a 64-bit length rather
than just a 32-bit one. Older kernels may not support the 64-bit length
variant. If this variant is attempted used on a kernel that doesn't
support 64-bit lengths, then the request will get errored with
**-EINVAL** in the results field of the CQE.

This function prepares an async [posix_fadvise] request. See that
man page for details.

# RETURN VALUE

None

# ERRORS

The CQE *res* field will contain the result of the operation. See the
related man page for details on possible values. Note that where
synchronous system calls will return **-1** on failure and set *errno*
to the actual error value, io_uring never uses *errno*. Instead it
returns the negated *errno* directly in the CQE *res* field.

# SEE ALSO

[io_uring_get_sqe], [io_uring_submit],
[io_uring_register], [posix_fadvise]
