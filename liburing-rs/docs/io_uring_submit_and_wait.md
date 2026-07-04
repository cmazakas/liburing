Submit requests to the submission queue and wait for completion.

# DESCRIPTION

The **io_uring_submit_and_wait**(3) function submits the next requests
from the submission queue belonging to the *ring* and waits for
*wait_nr* completion events.

After the caller retrieves a submission queue entry (SQE) with
**io_uring_get_sqe**(3) and prepares the SQE, it can be submitted with
**io_uring_submit_and_wait**(3)**.**

Ideally used with a ring setup with
**IORING_SETUP_SINGLE_ISSUER**|**IORING_SETUP_DEFER_TASKRUN** as that
will greatly reduce the number of context switches that an application
will see waiting on multiple requests.

# RETURN VALUE

On success **io_uring_submit_and_wait**(3) returns the number of
submitted submission queue entries. On failure it returns **-errno**.

# SEE ALSO

[io_uring_queue_init_params], [io_uring_get_sqe],
[io_uring_submit], [io_uring_submit_and_wait_timeout]
