Submit requests to the submission.
queue and wait for the completion with timeout

# DESCRIPTION

The [io_uring_submit_and_wait_timeout] function submits the next
requests from the submission queue belonging to the *ring* and waits for
*wait_nr* completion events, or until the timeout *ts* expires. The
completion events are stored in the *cqe_ptr* array.

The *sigmask* specifies the set of signals to block. If set, it is
equivalent to atomically executing the following calls:

```c
    sigset_t origmask;

    pthread_sigmask(SIG_SETMASK, &sigmask, &origmask);
    ret = io_uring_submit_and_wait_timeout(ring, cqe, wait_nr, ts, NULL);
    pthread_sigmask(SIG_SETMASK, &origmask, NULL);
```

After the caller retrieves a submission queue entry (SQE) with
[io_uring_get_sqe] and prepares the SQE, it can be submitted with
[io_uring_submit_and_wait_timeout]**.**

Ideally used with a ring setup with
**IORING_SETUP_SINGLE_ISSUER**|**IORING_SETUP_DEFER_TASKRUN** as that
will greatly reduce the number of context switches that an application
will see waiting on multiple requests.

# RETURN VALUE

On success [io_uring_submit_and_wait_timeout] returns the number of
submitted submission queue entries. On failure it returns **-errno**.
Note that in earlier versions of the liburing library, the return value
was 0 on success. The most common failure case is not receiving a
completion within the specified timeout, **-ETIME** is returned in this
case.

# SEE ALSO

[io_uring_queue_init_params], [io_uring_get_sqe],
[io_uring_submit], [io_uring_submit_and_wait],
[io_uring_wait_cqe]
