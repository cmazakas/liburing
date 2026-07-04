Mark one or more io_uring completion events as consumed.

# DESCRIPTION

The **io_uring_cq_advance**(3) function marks *nr* IO completions
belonging to the *ring* param as consumed.

After the caller has submitted a request with **io_uring_submit**(3),
the application can retrieve the completion with
**io_uring_wait_cqe**(3), **io_uring_peek_cqe**(3), or any of the other
CQE retrieval helpers, and mark it as consumed with
**io_uring_cqe_seen**(3).

The function **io_uring_cqe_seen**(3) calls the function
**io_uring_cq_advance**(3).

Completions must be marked as seen, so their slot can get reused.
Failure to do so will result in the same completion being returned on
the next invocation.

# RETURN VALUE

None

# SEE ALSO

[io_uring_submit], [io_uring_wait_cqe],
[io_uring_peek_cqe], [io_uring_wait_cqes],
[io_uring_wait_cqe_timeout], [io_uring_cqe_seen]
