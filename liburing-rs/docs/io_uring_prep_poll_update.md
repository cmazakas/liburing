Update an existing poll request.

# DESCRIPTION

The [io_uring_prep_poll_update] function prepares a poll update
request. The submission queue entry *sqe* is setup to update a poll
request identified by *old_user_data*, replacing it with the
*new_user_data* information. The *poll_mask* arguments contains the new
mask to use for the poll request, and *flags* argument contains modifier
flags telling io_uring what fields to update.

The *flags* modifier flags is a bitmask and may contain and OR'ed mask
of:

**IORING_POLL_UPDATE_EVENTS**\
If set, the poll update request will replace the existing events being
waited for with the ones specified in the *poll_mask* argument to the
function. Note that only the lower 16 bits of events can be updated.
This includes things like **EPOLLIN** and **EPOLLOUT .** Higher order
masks/settings are included as internal state, and cannot be modified.
That includes settings like **EPOLLONESHOT ,** **EPOLLEXCLUSIVE ,** and
**EPOLLET .** If an application wishes to modify these, it must
cancel/remove the existing poll request and arm a new one.

**IORING_POLL_UPDATE_USER_DATA**\
If set, the poll update request will update the existing user_data of
the request with the value passed in as the *new_user_data* argument.

**IORING_POLL_ADD_MULTI**\
If set, this will change the poll request from a singleshot to a
multishot request. This must be used along with
**IORING_POLL_UPDATE_EVENTS** as the event field must be updated to
enable multishot.

# RETURN VALUE

None

# ERRORS

These are the errors that are reported in the CQE *res* field. On
success, **0** is returned.

**-ENOENT**\
The request identified by *user_data* could not be located. This could
be because it completed before the cancelation request was issued, or if
an invalid identifier is used.

**-EINVAL**\
One of the fields set in the SQE was invalid.

**-EALREADY**\
The execution state of the request has progressed far enough that
cancelation is no longer possible. This should normally mean that it
will complete shortly, either successfully, or interrupted due to the
cancelation.

**-ECANCELED**\
**IORING_POLL_UPDATE_EVENTS** was set and an error occurred re-arming
the poll request with the new mask. The original poll request is
terminated if this happens, and that termination CQE will contain the
reason for the error re-arming.

# SEE ALSO

[io_uring_get_sqe], [io_uring_submit],
[io_uring_prep_poll_add], [io_uring_prep_poll_multishot]
