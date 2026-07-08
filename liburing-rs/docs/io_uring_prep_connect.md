Prepare a connect request

# DESCRIPTION

The [io_uring_prep_connect] function prepares a connect request.
The submission queue entry *sqe* is setup to use the file descriptor
*sockfd* to start connecting to the destination described by the socket
address at *addr* and of structure length *addrlen*.

This function prepares an async [connect](https://man7.org/linux/man-pages/man2/connect.2.html) request. See that man
page for details.

# RETURN VALUE

None

# ERRORS

The CQE *res* field will contain the result of the operation. See the
related man page for details on possible values. Note that where
synchronous system calls will return **-1** on failure and set *errno*
to the actual error value, io_uring never uses *errno*. Instead it
returns the negated *errno* directly in the CQE *res* field.

# NOTES

As with any request that passes in data in a struct, that data must
remain valid until the request has been successfully submitted. It need
not remain valid until completion. Once a request has been submitted,
the in-kernel state is stable. Very early kernels (5.4 and earlier)
required state to be stable until the completion occurred. Applications
can test for this behavior by inspecting the
**IORING_FEAT_SUBMIT_STABLE** flag passed back from
[io_uring_queue_init_params].

# SEE ALSO

[io_uring_get_sqe], [io_uring_submit], [connect](https://man7.org/linux/man-pages/man2/connect.2.html)
