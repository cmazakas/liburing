Returns if there are overflow entries waiting to move to the CQ ring.

# DESCRIPTION

The **io_uring_cq_has_overflow**(3) function informs the application if
CQ entries have overflowed and are waiting to be flushed to the CQ ring.
For example using **io_uring_get_events**(3)

# NOTES

Using this function is only valid if the ring has **IORING_FEAT_NODROP**
set, as it's checking for a flag set by kernels supporting that feature.
For really old kernels that don't support this feature, if CQE overflow
is experienced the CQEs are lost. If that happens, the CQ ring overflow
offset will get incremented.

# RETURN VALUE

True if there are CQ entries waiting to be flushed to the CQ ring.

# SEE ALSO

[io_uring_get_events]
