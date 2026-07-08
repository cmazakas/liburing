Set buf group for submission queue event

# DESCRIPTION

The [io_uring_sqe_set_buf_group] function sets the associated
buf_group of the *sqe* to *bgid*.

After the caller has requested a submission queue entry (SQE) with
[io_uring_get_sqe]**,** they can associate a buf_group with the SQE
used for multishot operations.

# RETURN VALUE

None

# SEE ALSO

[io_uring_get_sqe], [io_uring_cqe_set_data]
