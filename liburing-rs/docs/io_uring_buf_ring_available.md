Return number of unconsumed provided ring
buffer entries

# DESCRIPTION

The [io_uring_buf_ring_available] helper returns the number of
unconsumed (by the kernel) entries in the *br* provided buffer group
belonging to the io_uring *ring* and identified by the buffer group ID
*bgid.*

Since the head of the provided buffer ring is only visible to the
kernel, it's impossible to otherwise know how many unconsumed entries
exist in the given provided buffer ring. This function query the kernel
to return that number. Available since kernel 6.8.

# NOTES

The returned number of entries reflect the amount of unconsumed entries
at the time that it was queried. If inflight IO exists that may consume
provided buffers from this buffer group, then the returned value is
inherently racy.

# RETURN VALUE

Returns the number of unconsumed entries on success, which may be 0. In
case of error, may return **-ENOENT** if the specified buffer group
doesn't exist, or **-EINVAL** if the buffer group isn't of the correct
type, or if the kernel doesn't support this feature.

# SEE ALSO

[io_uring_register_buf_ring], [io_uring_buf_ring_add],
[io_uring_buf_ring_cq_advance]
