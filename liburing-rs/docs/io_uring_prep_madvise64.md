Prepare a madvise request

# DESCRIPTION

The [io_uring_prep_madvise] function prepares an madvise request.
The submission queue entry *sqe* is setup to start an madvise operation
at the virtual address of *addr* and of *len* length in bytes, giving it
the advise located in *advice*.

The [io_uring_prep_madvise64] function works like
[io_uring_prep_madvise] except that it takes a 64-bit length rather
than just a 32-bit one. Older kernels may not support the 64-bit length
variant. If this variant is attempted used on a kernel that doesn't
support 64-bit lengths, then the request will get errored with
**-EINVAL** in the results field of the CQE.

This function prepares an async [madvise](https://man7.org/linux/man-pages/man2/madvise.2.html) request. See that man
page for details.

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
[io_uring_register], [madvise](https://man7.org/linux/man-pages/man2/madvise.2.html)
