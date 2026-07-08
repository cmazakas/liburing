Prepare a nop request

# DESCRIPTION

The [io_uring_prep_nop128] function prepares nop (no operation)
request for a 128-byte entry. The submission queue entry *sqe* does not
require any additional setup.

# RETURN VALUE

None

# ERRORS

None

# SEE ALSO

[io_uring_prep_nop], [io_uring_get_sqe],
[io_uring_submit],
