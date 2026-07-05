Wait for completions with both batch.
and normal timeout

# DESCRIPTION

The [io_uring_wait_cqes_min_timeout] waits for completions from the
submission queue belonging to the *ring* and waits for *wait_nr*
completion events, or until the timeout *ts* expires. The completion
events are stored in the *cqe_ptr* array. If non-zero, *min_wait_usec*
denotes a timeout for the *wait_nr* batch.

The *sigmask* specifies the set of signals to block. If set, it is
equivalent to atomically executing the following calls:

```c
    sigset_t origmask;

    pthread_sigmask(SIG_SETMASK, &sigmask, &origmask);
    ret = io_uring_wait_cqes_min_timeout(ring, cqe, wait_nr, ts, min_wait, NULL);
    pthread_sigmask(SIG_SETMASK, &origmask, NULL);
```

This works like [io_uring_submit_and_wait_min_timeout] except that
it doesn't submit requests. See that man page for a description for how
the min timeout waiting works.

Available since 6.12.

# RETURN VALUE

On success [io_uring_wait_cqes_min_timeout] returns the 0.On
failure it returns **-errno**. If the kernel doesn't support this
functionality, **-EINVAL** will be returned. See note on the feature
flag. The most common failure case is not receiving a completion within
the specified timeout, **-ETIME** is returned in this case.

# SEE ALSO

[io_uring_wait_cqe], [io_uring_wait_cqes],
[io_uring_wait_cqe_timeout], [io_uring_wait_cqes],
[io_uring_submit_and_wait_min_timeout]
