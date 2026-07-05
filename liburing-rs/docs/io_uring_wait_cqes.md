Wait for one or more io_uring completion events.

# DESCRIPTION

The [io_uring_wait_cqes] function returns *wait_nr* IO completions
from the queue belonging to the *ring* param, waiting for them if
necessary or until the timeout *ts* expires.

The *sigmask* specifies the set of signals to block. If set, it is
equivalent to atomically executing the following calls:

```c
    sigset_t origmask;

    pthread_sigmask(SIG_SETMASK, &sigmask, &origmask);
    ret = io_uring_wait_cqes(ring, cqe, wait_nr, ts, NULL);
    pthread_sigmask(SIG_SETMASK, &origmask, NULL);
```

The *cqe_ptr* param is filled in on success with the first CQE. Callers
of this function should use [io_uring_for_each_cqe] to iterate all
available CQEs.

If *ts* is specified and an older kernel without **IORING_FEAT_EXT_ARG**
is used, the application does not need to call [io_uring_submit]
before calling [io_uring_wait_cqes]. For newer kernels with that
feature flag set, there is no implied submit when waiting for a request.

If *ts* is **NULL ,** then this behaves like [io_uring_wait_cqe] in
that it will wait forever for an event.

# RETURN VALUE

On success [io_uring_wait_cqes] returns 0 and the cqe_ptr param is
filled in. On failure it returns **-errno**. If a timeout occurs, it
will return **-ETIME**.

# SEE ALSO

[io_uring_submit], [io_uring_for_each_cqe],
[io_uring_wait_cqe_timeout], [io_uring_wait_cqe]
