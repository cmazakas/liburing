Check if an io_uring completion event is available

# DESCRIPTION

The [io_uring_peek_cqe] function returns an IO completion from the
queue belonging to the *ring* param, if one is readily available. On
successful return, *cqe_ptr* param is filled with a valid CQE entry.

This function does not enter the kernel to wait for an event, an event
is only returned if it's already available in the CQ ring.

The [io_uring_peek_batch_cqe] function returns up to *count*
request completions in *cqe_ptrs* belonging to the *ring* param, if they
are readily available. It will not enter the kernel, unless the CQ ring
is in an overflow condition. Upon successful return, *cqe_ptrs* are
filled with the number of events indicated by the return value.

# RETURN VALUE

On success [io_uring_peek_cqe] returns **0** and the cqe_ptr
parameter is filled in. On success [io_uring_peek_batch_cqe]
returns the number of completions filled in. On failure,
[io_uring_peek_cqe] may return **-EAGAIN**.

# SEE ALSO

[io_uring_submit], [io_uring_wait_cqes],
[io_uring_wait_cqe]
