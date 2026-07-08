Prepare a remove buffers request

# DESCRIPTION

The [io_uring_prep_remove_buffers] function prepares a request for
removing previously supplied buffers. The submission queue entry *sqe*
is setup to remove *nr* number of buffers from the buffer group ID
indicated by *bgid*.

# RETURN VALUE

None

# ERRORS

These are the errors that are reported in the CQE *res* field. On
success, *res* will contain the number of successfully removed buffers.
On error, the following errors can occur.

**-ENOMEM**\
The kernel was unable to allocate memory for the request.

**-EINVAL**\
One of the fields set in the SQE was invalid.

**-ENOENT**\
No buffers exist at the specified *bgid* buffer group ID.

# SEE ALSO

[io_uring_get_sqe], [io_uring_submit],
[io_uring_register], [io_uring_prep_provide_buffers]
