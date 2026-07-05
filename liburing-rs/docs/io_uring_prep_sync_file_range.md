Prepare a sync_file_range request.

# DESCRIPTION

The [io_uring_prep_sync_file_range] function prepares a
sync_file_range request. The submission queue entry *sqe* is setup to
use the file descriptor *fd* that should get *len* bytes synced started
at offset *offset* and with modifier flags in the *flags* argument.

This function prepares an async [sync_file_range](https://man7.org/linux/man-pages/man2/sync_file_range.2.html) request. See that
man page for details on the arguments.

# RETURN VALUE

None

# ERRORS

The CQE *res* field will contain the result of the operation. See the
related man page for details on possible values. Note that where
synchronous system calls will return **-1** on failure and set *errno*
to the actual error value, io_uring never uses *errno*. Instead it
returns the negated *errno* directly in the CQE *res* field.

# SEE ALSO

[io_uring_get_sqe], [io_uring_submit], [sync_file_range](https://man7.org/linux/man-pages/man2/sync_file_range.2.html)
