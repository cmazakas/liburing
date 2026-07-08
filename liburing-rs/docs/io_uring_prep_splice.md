Prepare an splice request

# DESCRIPTION

The [io_uring_prep_splice] function prepares a splice request. The
submission queue entry *sqe* is setup to use as input the file
descriptor *fd_in* at offset *off_in*, splicing data to the file
descriptor at *fd_out* and at offset *off_out*. *nbytes* bytes of data
should be spliced between the two descriptors. *splice_flags* are
modifier flags for the operation. See [splice](https://man7.org/linux/man-pages/man2/splice.2.html) for the generic
splice flags.

If *fd_out* is a direct descriptor, **IOSQE_FIXED_FILE** can be set in
the SQE to indicate that. For the input file, the io_uring specific
**SPLICE_F_FD_IN_FIXED** can be set in *splice_flags* and *fd_in* given
as a registered file descriptor offset.

If *fd_in* refers to a pipe, *off_in* is ignored and must be set to -1.

If *fd_in* does not refer to a pipe and *off_in* is -1, then *nbytes*
are read from *fd_in* starting from the file offset, which is
incremented by the number of bytes read.

If *fd_in* does not refer to a pipe and *off_in* is not -1, then the
starting offset of *fd_in* will be *off_in*.

The same rules apply to *fd_out* and *off_out*.

This function prepares an async [splice](https://man7.org/linux/man-pages/man2/splice.2.html) request. See that man page
for details.

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
[io_uring_register], [splice](https://man7.org/linux/man-pages/man2/splice.2.html)

# NOTES

Note that even if *fd_in* or *fd_out* refers to a pipe, the splice
operation can still fail with **EINVAL** if one of the fd doesn't
explicitly support splice operation, e.g. reading from terminal is
unsupported from kernel 5.7 to 5.11.

Despite accepting an unsigned number of bytes, this function can
transfer at most INT_MAX bytes per call (the maximum for the underlying
syscall interface). In practice, limits as low as 65536 have been
observed (just like with [splice](https://man7.org/linux/man-pages/man2/splice.2.html) itself).
