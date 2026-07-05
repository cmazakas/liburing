Flush outstanding requests to CQE ring.

# DESCRIPTION

The [io_uring_get_events] function runs outstanding work and
flushes completion events to the CQE ring.

There can be events needing to be flushed if the ring was full and had
overflowed. Alternatively if the ring was setup with the
**IORING_SETUP_DEFER_TASKRUN** flag then this will process outstanding
tasks, possibly resulting in more CQEs.

# RETURN VALUE

On success [io_uring_get_events] returns 0. On failure it returns
**-errno**.

# SEE ALSO

[io_uring_get_sqe], [io_uring_submit_and_get_events],
[io_uring_cq_has_overflow]
