Prepare a pipe creation request.

# DESCRIPTION

The [io_uring_prep_pipe] function prepares a pipe creation request.
The submission queue entry *sqe* is setup to create a pipe with the
created descriptors being copied to the array indicated by *fds* and
using *pipe_flags* as the pipe creation flags. See **pipe2(2)** for
details on the flags accepted.

The [io_uring_prep_pipe_direct] function works in the same way,
however it uses fixed/registered file descriptors rather than normal
file descriptors. This helper takes an additional *file_index* argument,
which can set to either an explicit direct descriptor offset to create
the two pipe file descriptors at, or it can be set to
**IORING_FILE_INDEX_ALLOC** to let io_uring pick any available
descriptors for the read and write side of the pipe. If a specific index
is given, the read side of the pipe will be created at that offset, if
free, and the write side will be created at the next (+1) index. Both of
these must be currently unused, or the operation will fail. Also see
[io_uring_prep_accept_direct] or [io_uring_prep_socket_direct]
for details on the *file_index* parameter.

For both the direct and normal file descriptor pipe request, the
resulting input/read side of the pipe will be stored in *fds\[0\]* and
the output/write side of the pipe will be stored in *fds\[1\]* upon
successful completion of this request.

This function prepares an async [pipe2](https://man7.org/linux/man-pages/man2/pipe.2.html) request. See that man page
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

[io_uring_get_sqe], [io_uring_submit], [pipe2](https://man7.org/linux/man-pages/man2/pipe.2.html),
[io_uring_prep_accept_direct], [io_uring_prep_socket_direct]
