Wait for one io_uring completion event with
timeout

# DESCRIPTION

The [io_uring_wait_cqe_timeout] function waits for one IO
completion to be available from the queue belonging to the *ring* param,
waiting for it if necessary or until the timeout *ts* expires. If an
event is already available in the ring when invoked, no waiting will
occur.

The *cqe_ptr* param is filled in on success.

If *ts* is specified and an older kernel without **IORING_FEAT_EXT_ARG**
is used, the application does not need to call [io_uring_submit]
before calling [io_uring_wait_cqes]. For newer kernels with that
feature flag set, there is no implied submit when waiting for a request.

If *ts* is **NULL ,** then this behaves like [io_uring_wait_cqe] in
that it will wait forever for an event.

# RETURN VALUE

On success [io_uring_wait_cqe_timeout] returns 0 and the cqe_ptr
param is filled in. On failure it returns **-errno**. The return value
indicates the result of waiting for a CQE, and it has no relation to the
CQE result itself. If a timeout occurs, it will return **-ETIME**.

# SEE ALSO

[io_uring_submit], [io_uring_wait_cqes],
[io_uring_wait_cqe]
