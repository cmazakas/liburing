Wait for one io_uring completion event

# DESCRIPTION

The [io_uring_wait_cqe] function waits for an IO completion from
the queue belonging to the *ring* param, waiting for it if necessary. If
an event is already available in the ring when invoked, no waiting will
occur. The *cqe_ptr* param is filled in on success.

After the caller has submitted a request with [io_uring_submit],
the application can retrieve the completion with
[io_uring_wait_cqe].

# RETURN VALUE

On success [io_uring_wait_cqe] returns 0 and the cqe_ptr param is
filled in. On failure it returns **-errno**. The return value indicates
the result of waiting for a CQE, and it has no relation to the CQE
result itself.

# SEE ALSO

[io_uring_submit], [io_uring_wait_cqe_timeout],
[io_uring_wait_cqes]
