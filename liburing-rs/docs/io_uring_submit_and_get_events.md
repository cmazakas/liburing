Submit requests to the submission queue.
and flush completions

# DESCRIPTION

The [io_uring_submit_and_get_events] function submits the next
events to the submission queue as with [io_uring_submit]**.** After
submission it will flush CQEs as with [io_uring_get_events]**.**

The benefit of this function is that it does both with only one system
call.

# RETURN VALUE

On success [io_uring_submit_and_get_events] returns the number of
submitted submission queue entries. On failure it returns **-errno**.

# SEE ALSO

[io_uring_submit], [io_uring_get_events]
