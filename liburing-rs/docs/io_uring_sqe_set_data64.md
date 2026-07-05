Set user data for submission queue event.

# DESCRIPTION

The [io_uring_sqe_set_data] function stores a *user_data* pointer
with the submission queue entry *sqe*.

The [io_uring_sqe_set_data64] function stores a 64-bit *data* value
with the submission queue entry *sqe*.

After the caller has requested a submission queue entry (SQE) with
[io_uring_get_sqe]**,** they can associate a data pointer or value
with the SQE. Once the completion arrives, the function
[io_uring_cqe_get_data] or [io_uring_cqe_get_data64] can be
called to retrieve the data pointer or value associated with the
submitted request.

Note that if neither of these functions are called, or the *user_data*
field in the *sqe* isn't set manually either, then the field may contain
a value from a previous use of this sqe. If an application relies on
always having a valid *user_data* value present, it must always assign
one to each sqe.

# RETURN VALUE

None

# SEE ALSO

[io_uring_get_sqe], [io_uring_cqe_get_data]
