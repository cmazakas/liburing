Get user data for completion event

# DESCRIPTION

The [io_uring_cqe_get_data] function returns the user_data with the
completion queue entry *cqe* as a data pointer.

The [io_uring_cqe_get_data64] function returns the user_data with
the completion queue entry *cqe* as a 64-bit data value.

After the caller has received a completion queue entry (CQE) with
[io_uring_wait_cqe], the application can call
[io_uring_cqe_get_data] or [io_uring_cqe_get_data64] function
to retrieve the *user_data* value. This requires that *user_data* has
been set earlier with the function [io_uring_sqe_set_data] or
[io_uring_sqe_set_data64].

# RETURN VALUE

If the *user_data* value has been set before submitting the request, it
will be returned. Otherwise, the return value is undefined.

# SEE ALSO

[io_uring_get_sqe], [io_uring_sqe_set_data],
[io_uring_submit]
