Prepare an fsync request

# DESCRIPTION

The [io_uring_prep_fsync] function prepares an fsync request. The
submission queue entry *sqe* is setup to use the file descriptor *fd*
that should get synced, with the modifier flags indicated by the *flags*
argument.

This function prepares an fsync request. It can act either like an
[fsync](https://man7.org/linux/man-pages/man2/fsync.2.html) operation, which is the default behavior. If
**IORING_FSYNC_DATASYNC** is set in the *flags* argument, then it
behaves like [fdatasync](https://man7.org/linux/man-pages/man2/fdatasync.2.html). If no range is specified, the *fd* will
be synced from 0 to end-of-file.

It's possible to specify a range to sync, if one is desired. If the
*off* field of the SQE is set to non-zero, then that indicates the
offset to start syncing at. If *len* is set in the SQE, then that
indicates the size in bytes to sync from the offset. Note that these
fields are not accepted by this helper, so they have to be set manually
in the SQE after calling this prep helper.

# RETURN VALUE

None

# ERRORS

The CQE *res* field will contain the result of the operation. See the
related man page for details on possible values. Note that where
synchronous system calls will return **-1** on failure and set *errno*
to the actual error value, io_uring never uses *errno*. Instead it
returns the negated *errno* directly in the CQE *res* field.

# SEE ALSO

[io_uring_get_sqe], [io_uring_submit], [fsync](https://man7.org/linux/man-pages/man2/fsync.2.html),
[fdatasync](https://man7.org/linux/man-pages/man2/fdatasync.2.html)
