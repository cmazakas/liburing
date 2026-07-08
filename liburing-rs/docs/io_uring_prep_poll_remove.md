Prepare a poll deletion request

# DESCRIPTION

The [io_uring_prep_poll_remove] function prepares a poll removal
request. The submission queue entry *sqe* is setup to remove a poll
request identified by *user_data*

Works like [io_uring_prep_cancel] except only looks for poll
requests. Apart from that, behavior is identical. See that man page for
specific details.

# RETURN VALUE

None

# ERRORS

These are the errors that are reported in the CQE *res* field. On
success, **0** is returned.

**-ENOENT**  
The request identified by *user_data* could not be located. This could
be because it completed before the cancelation request was issued, or if
an invalid identifier is used.

**-EINVAL**  
One of the fields set in the SQE was invalid.

**-EALREADY**  
The execution state of the request has progressed far enough that
cancelation is no longer possible. This should normally mean that it
will complete shortly, either successfully, or interrupted due to the
cancelation.

# SEE ALSO

[io_uring_get_sqe], [io_uring_submit],
[io_uring_prep_cancel]
