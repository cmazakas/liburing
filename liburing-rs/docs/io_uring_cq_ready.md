Returns number of unconsumed ready entries in the CQ
ring

# DESCRIPTION

The [io_uring_cq_ready] function returns the number of unconsumed
entries that are ready belonging to the *ring* param.

# RETURN VALUE

Returns the number of unconsumed ready entries in the CQ ring.

# SEE ALSO

[io_uring_submit], [io_uring_wait_cqe]
