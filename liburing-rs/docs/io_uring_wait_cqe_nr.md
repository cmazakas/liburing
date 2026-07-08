Wait for one or more io_uring completion events

# DESCRIPTION

The [io_uring_wait_cqe_nr] function returns *wait_nr* IO completion
events from the queue belonging to the *ring* param, waiting for it if
necessary. If the requested number of events are already available in
the ring when invoked, no waiting will occur. The *cqe_ptr* param is
filled in on success.

After the caller has submitted a request with [io_uring_submit],
the application can retrieve the completion with
[io_uring_wait_cqe].

Ideally used with a ring setup with
**IORING_SETUP_SINGLE_ISSUER**|**IORING_SETUP_DEFER_TASKRUN** as that
will greatly reduce the number of context switches that an application
will see waiting on multiple requests.

# RETURN VALUE

On success [io_uring_wait_cqe_nr] returns 0 and the cqe_ptr param
is filled in. On failure it returns **-errno**. The return value
indicates the result of waiting for a CQE, and it has no relation to the
CQE result itself.

# SEE ALSO

[io_uring_queue_init_params], [io_uring_submit],
[io_uring_wait_cqes]
