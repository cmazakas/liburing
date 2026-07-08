Return the number of CQ ring slots consumed by a CQE

# DESCRIPTION

The [io_uring_cqe_nr] function returns the number of CQ ring slots
consumed by *cqe*. For normal 16-byte CQEs, this returns 1. For 32-byte
CQEs (when **IORING_CQE_F_32** is set in the CQE flags), this returns 2.

This function is useful when advancing the CQ ring with
[io_uring_cq_advance] on rings that use **IORING_SETUP_CQE_MIXED**
where both 16-byte and 32-byte CQEs may be present.

# RETURN VALUE

Returns 1 for normal CQEs, or 2 for 32-byte CQEs.

# SEE ALSO

[io_uring_cq_advance], [io_uring_cqe_seen],
[io_uring_setup]
