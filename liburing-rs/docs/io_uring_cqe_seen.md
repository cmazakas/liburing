Mark io_uring completion event as consumed.

# DESCRIPTION

The **io_uring_cqe_seen**(3) function marks the IO completion *cqe*
belonging to the *ring* param as consumed.

After the caller has submitted a request with **io_uring_submit**(3),
the application can retrieve the completion with
**io_uring_wait_cqe**(3), **io_uring_peek_cqe**(3), or any of the other
CQE retrieval helpers, and mark it as consumed with
**io_uring_cqe_seen**(3).

Completions must be marked as completed so their slot can get reused.

# RETURN VALUE

None

# SEE ALSO

[io_uring_submit], [io_uring_peek_cqe],
[io_uring_wait_cqe], [io_uring_wait_cqes],
[io_uring_wait_cqe_timeout]
