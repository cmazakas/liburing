Prepare a request to update an existing
timeout

# DESCRIPTION

These functions modify or cancel an existing timeout request. The
submission queue entry *sqe* is setup to arm a timeout update or removal
specified by *user_data* and with modifier flags given by *flags*.
Additionally, the update request includes a *ts* structure, which
contains new timeout information.

For an update request, the *flags* member may contain a bitmask of the
following values:

**IORING_TIMEOUT_ABS**\
The value specified in *ts* is an absolute value rather than a relative
one.

The timeout remove command does not currently accept any flags.

# RETURN VALUE

None

# ERRORS

These are the errors that are reported in the CQE *res* field. On
success, **0** is returned.

**-ENOENT**\
The timeout identified by *user_data* could not be found. It may be
invalid, or triggered before the update or removal request was
processed.

**-EALREADY**\
The timeout identified by *user_data* is already firing and cannot be
canceled.

**-EINVAL**\
One of the fields set in the SQE was invalid. For example, two
clocksources were given, or the specified timeout seconds or nanoseconds
were \< 0.

**-EFAULT**\
io_uring was unable to access the data specified by *ts*.

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
[io_uring_prep_timeout]
