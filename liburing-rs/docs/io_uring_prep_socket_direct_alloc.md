Prepare a socket creation request.

# DESCRIPTION

The [io_uring_prep_socket] function prepares a socket creation
request. The submission queue entry *sqe* is setup to use the
communication domain defined by *domain* and use the communication type
defined by *type* and the protocol set by *protocol*. The *flags*
argument are currently unused.

The [io_uring_prep_socket_direct] helper works just like
[io_uring_prep_socket], except it maps the socket to a direct
descriptor rather than return a normal file descriptor. The *file_index*
argument should be set to the slot that should be used for this socket.

The [io_uring_prep_socket_direct_alloc] helper works just like
[io_uring_prep_socket_direct], except it allocates a new direct
descriptor rather than pass a free slot in. It is equivalent to using
[io_uring_prep_socket_direct] with **IORING_FILE_INDEX_ALLOC** as
the *file_index .* Upon completion, the *res* field of the CQE will
return the direct slot that was allocated for the socket.

If the direct variants are used, the application must first have
registered a file table using [io_uring_register_files] of the
appropriate size. Once registered, a direct socket request may use any
entry in that table, as long as it is within the size of the registered
table. If a specified entry already contains a file, the file will first
be removed from the table and closed. It's consistent with the behavior
of updating an existing file with [io_uring_register_files_update].

For a direct descriptor socket request, the *file_index* argument can be
set to **IORING_FILE_INDEX_ALLOC**, In this case a free entry in
io_uring file table will be used automatically and the file index will
be returned as CQE *res*. **-ENFILE** is otherwise returned if there is
no free entries in the io_uring file table.

These functions prepare an async [socket] request. See that man
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

[io_uring_get_sqe], [io_uring_submit], [socket]
