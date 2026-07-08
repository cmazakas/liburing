Number of unconsumed or unsubmitted entries in the
SQ ring

# DESCRIPTION

The [io_uring_sq_ready] function returns the number of unconsumed
(if SQPOLL) or unsubmitted entries that exist in the SQ ring belonging
to the *ring* param.

Usage of this function only applies if the ring has been setup with
**IORING_SETUP_SQPOLL,** where request submissions, and hence
consumption from the SQ ring, happens through a polling thread.

# RETURN VALUE

Returns the number of unconsumed or unsubmitted entries in the SQ ring.

# SEE ALSO

[io_uring_cq_ready]
