Submit requests to the submission queue.

# DESCRIPTION

The [io_uring_submit] function submits the next events to the
submission queue belonging to the *ring*.

After the caller retrieves a submission queue entry (SQE) with
[io_uring_get_sqe] and prepares the SQE using one of the provided
helpers, it can be submitted with [io_uring_submit]**.**

# RETURN VALUE

On success [io_uring_submit] returns the number of submitted
submission queue entries, if SQPOLL is not used. If SQPOLL is used, the
return value may report a higher number of submitted entries than
actually submitted. If the user requires accurate information about how
many submission queue entries have been successfully submitted, while
using SQPOLL, the user must fall back to repeatedly submitting a single
submission queue entry. On failure it returns **-errno**.

# NOTES

For any request that passes in data in a struct, that data must remain
valid until the request has been successfully submitted. It need not
remain valid until completion. Once a request has been submitted, the
in-kernel state is stable. Very early kernels (5.4 and earlier) required
state to be stable until the completion occurred. Applications can test
for this behavior by inspecting the **IORING_FEAT_SUBMIT_STABLE** flag
passed back from [io_uring_queue_init_params]. In general, the man
pages for the individual prep helpers will have a note mentioning this
fact as well, if required for the given command.

# SEE ALSO

[io_uring_get_sqe], [io_uring_submit_and_wait],
[io_uring_submit_and_wait_timeout]
