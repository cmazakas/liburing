Prepare a tee request.

# DESCRIPTION

The [io_uring_prep_tee] function prepares a tee request. The
submission queue entry *sqe* is setup to use as input the file
descriptor *fd_in* and as output the file descriptor *fd_out*
duplicating up to *nbytes* bytes worth of data. *splice_flags* are
modifier flags for the operation. See [tee](https://man7.org/linux/man-pages/man1/tee.1.html) for the generic splice
flags.

If *fd_out* is a direct descriptor, **IOSQE_FIXED_FILE** can be set in
the SQE to indicate that. For the input file, the io_uring specific
**SPLICE_F_FD_IN_FIXED** can be set and *fd_in* given as a registered
file descriptor offset.

This function prepares an async [tee](https://man7.org/linux/man-pages/man1/tee.1.html) request. See that man page
for details.

# RETURN VALUE

None

# ERRORS

The CQE *res* field will contain the result of the operation. See the
related man page for details on possible values. Note that where
synchronous system calls will return **-1** on failure and set *errno*
to the actual error value, io_uring never uses *errno*. Instead it
returns the negated *errno* directly in the CQE *res* field.

# NOTES

Despite accepting an unsigned number of bytes, this function can
transfer at most INT_MAX bytes per call (the maximum for the underlying
syscall interface). In practice, limits as low as 65536 have been
observed (just like with [tee](https://man7.org/linux/man-pages/man1/tee.1.html) itself).

# SEE ALSO

[io_uring_get_sqe], [io_uring_submit],
[io_uring_register], [splice](https://man7.org/linux/man-pages/man2/splice.2.html), [tee](https://man7.org/linux/man-pages/man1/tee.1.html)
