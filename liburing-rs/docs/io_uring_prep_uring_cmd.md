Prepare a uring_cmd request

# DESCRIPTION

The [io_uring_prep_uring_cmd] function prepares uring_cmd (fd
specific) request. The submission queue entry *sqe* is setup to use the
filedescriptor *fd* to send file descriptor specific *cmd_op*.

The reserved fields are initialized to 0. Otherwise the caller has to
set up any submission queue entry's operation specific fields.

# RETURN VALUE

None

# ERRORS

None

# SEE ALSO

[io_uring_prep_uring_cmd128], [io_uring_get_sqe],
[io_uring_submit],
