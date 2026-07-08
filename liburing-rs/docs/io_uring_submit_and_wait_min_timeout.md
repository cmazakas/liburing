Submit requests to the submission
queue and wait for the completion with both batch and normal timeout

# DESCRIPTION

The [io_uring_submit_and_wait_min_timeout] function submits the
next requests from the submission queue belonging to the *ring* and
waits for *wait_nr* completion events, or until the timeout *ts*
expires. The completion events are stored in the *cqe_ptr* array. If
non-zero, *min_wait_usec* denotes a timeout for the *wait_nr* batch.

The *sigmask* specifies the set of signals to block. If set, it is
equivalent to atomically executing the following calls:

    sigset_t origmask;

    pthread_sigmask(SIG_SETMASK, &sigmask, &origmask);
    ret = io_uring_submit_and_wait_min_timeout(ring, cqe, wait_nr, ts, min_wait, NULL);
    pthread_sigmask(SIG_SETMASK, &origmask, NULL);

This works like [io_uring_submit_and_wait_timeout] with the twist
that it applies a minimum timeout for the requested batch size of
requests to wait for. While [io_uring_submit_and_wait_timeout]
waits for as long as *ts* specifies, or until *wait_nr* of request
completions have been received, if *min_wait_usec* is set, then this is
the timeout for the *wait_nr* number of requests. If the requested
number of completions have been received within *min_wait_usec* number
of microseconds, then the function returns successfully. If that isn't
the case, once *min_wait_usec* time has passed, control is returned if
any completions have been posted. If no completions have been posted,
the kernel switches to a normal wait of up to *ts* specified amount of
time, subtracting the time already waited. If any completions are posted
after this happens, control is returned immediately to the application.

This differs from the normal timeout waiting in that waiting continues
post the initial timeout, if and only if no completions have been
posted. It's meant to be used to optimize batch waiting for requests,
where the application allots a budget of *min_wait_usec* amount of time
to receive *wait_nr* number of completions, but if none are received,
then waiting can continue without incurring extra context switches or
extra kernel/user transitions.

Can be used with any ring, as long as the kernel supports it. Support is
indicated by checking the **IORING_FEAT_MIN_TIMEOUT** feature flag after
the ring has been setup. Ideally used with a ring setup with
**IORING_SETUP_SINGLE_ISSUER**|**IORING_SETUP_DEFER_TASKRUN** as that
will greatly reduce the number of context switches that an application
will see waiting on multiple requests.

Available since 6.12.

# RETURN VALUE

On success [io_uring_submit_and_wait_min_timeout] returns the
number of submitted submission queue entries. On failure it returns
**-errno**. If the kernel doesn't support this functionality,
**-EINVAL** will be returned. See note on the feature flag. The most
common failure case is not receiving a completion within the specified
timeout, **-ETIME** is returned in this case.

# SEE ALSO

[io_uring_queue_init_params], [io_uring_get_sqe],
[io_uring_submit], [io_uring_submit_and_wait],
[io_uring_submit_and_wait_timeout], [io_uring_wait_cqe]
