Prepare a timeout request

# DESCRIPTION

The [io_uring_prep_timeout] function prepares a timeout request.
The submission queue entry *sqe* is setup to arm a timeout specified by
*ts* and with a timeout count of *count* completion entries. The *flags*
argument holds modifier flags for the request.

This request type can be used as a timeout waking anyone sleeping for
events on the CQ ring. The *flags* argument may contain:

**IORING_TIMEOUT_ABS**\
The value specified in *ts* is an absolute value rather than a relative
one.

**IORING_TIMEOUT_BOOTTIME**\
The boottime clock source should be used.

**IORING_TIMEOUT_REALTIME**\
The realtime clock source should be used.

**IORING_TIMEOUT_ETIME_SUCCESS**\
Consider an expired timeout a success in terms of the posted completion.
This means it will not sever dependent links, as a failed request
normally would. The posted CQE result code will still contain **-ETIME**
in the *res* value.

**IORING_TIMEOUT_MULTISHOT**\
The request will return multiple timeout completions. The completion
flag IORING_CQE_F_MORE is set if more timeouts are expected. The value
specified in *count* is the number of repeats. A value of 0 means the
timeout is indefinite and can only be stopped by a removal request.
Available since the 6.4 kernel.

**IORING_TIMEOUT_IMMEDIATE_ARG**\
The timeout value is stored directly in the SQE as a nanosecond value
rather than as a pointer to a **struct \_\_kernel_timespec.** When this
flag is set, the *ts* argument to [io_uring_prep_timeout] is
reinterpreted as a nanosecond value (cast to a **\_\_u64**) rather than
a pointer. This avoids the need to keep a timespec structure valid in
user memory until the request is submitted. Available since the 7.1
kernel.

If no alternate clock source is given in the above flags, then
**CLOCK_MONOTONIC** is used.

The timeout completion event will trigger if either the specified
timeout has occurred, or the specified number of events to wait for have
been posted to the CQ ring.

# RETURN VALUE

None

# ERRORS

These are the errors that are reported in the CQE *res* field. On
success, **0** is returned.

**-ETIME**\
The specified timeout occurred and triggered the completion event.

**-EINVAL**\
One of the fields set in the SQE was invalid. For example, two
clocksources were given, the specified timeout seconds or nanoseconds
were \< 0.

**-EFAULT**\
io_uring was unable to access the data specified by *ts*.

**-ECANCELED**\
The timeout was canceled by a removal request.

# NOTES

As with any request that passes in data in a struct, that data must
remain valid until the request has been successfully submitted. It need
not remain valid until completion. Once a request has been submitted,
the in-kernel state is stable. Very early kernels (5.4 and earlier)
required state to be stable until the completion occurred. Applications
can test for this behavior by inspecting the
**IORING_FEAT_SUBMIT_STABLE** flag passed back from
[io_uring_queue_init_params].

# SEE ALSO

[io_uring_get_sqe], [io_uring_submit],
[io_uring_prep_timeout_remove], [io_uring_prep_timeout_update]
