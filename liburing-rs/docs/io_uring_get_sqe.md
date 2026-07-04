Get the next available submission queue entry from the submission queue.

# DESCRIPTION

The **io_uring_get_sqe**(3) function gets the next available submission
queue entry from the submission queue belonging to the *ring* param.

On success **io_uring_get_sqe**(3) returns a pointer to the submission
queue entry. On failure NULL is returned.

If a submission queue entry is returned, it should be filled out via one
of the prep functions such as **io_uring_prep_read**(3) and submitted
via **io_uring_submit**(3).

Note that neither **io_uring_get_sqe** nor the prep functions set (or
clear) the **user_data** field of the SQE. If the caller expects
**io_uring_cqe_get_data**(3) or **io_uring_cqe_get_data64**(3) to return
valid data when reaping IO completions, either
**io_uring_sqe_set_data**(3) or **io_uring_sqe_set_data64**(3) **MUST**
have been called before submitting the request.

# RETURN VALUE

**io_uring_get_sqe**(3) returns a pointer to the next submission queue
event on success and NULL on failure. If NULL is returned, the SQ ring
is currently full and entries must be submitted for processing before
new ones can get allocated.

# SEE ALSO

[io_uring_submit], [io_uring_sqe_set_data]
