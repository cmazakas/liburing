Prepare a listen request.

# DESCRIPTION

The [io_uring_prep_listen] function prepares a listen request. The
submission queue entry *sqe* is setup to place the socket file
descriptor pointed by *sockfd* into a state to accept incoming
connections. The parameter *backlog*, defines the maximum length of the
queue of pending connections.

This function prepares an async [listen] request. See that man page
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

[io_uring_get_sqe], [io_uring_submit], [listen]
