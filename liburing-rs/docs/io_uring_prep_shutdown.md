Prepare a shutdown request

# DESCRIPTION

The [io_uring_prep_shutdown] function prepares a shutdown request.
The submission queue entry *sqe* is setup to use the file descriptor
*sockfd* that should be shutdown with the *how* argument.

This function prepares an async [shutdown](https://man7.org/linux/man-pages/man2/shutdown.2.html) request. See that man
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

[io_uring_get_sqe], [io_uring_submit], [shutdown](https://man7.org/linux/man-pages/man2/shutdown.2.html)
