Advance index of provided buffer and CQ ring.

# DESCRIPTION

The **io_uring_buf_ring_cq_advance**(3) commits *count* previously added
buffers to the shared buffer ring *br*, making them visible to the
kernel and hence consumable. This passes ownership of the buffer to the
ring. At the same time, it advances the CQ ring of *ring* by *count*
amount. This effectively bundles both a **io_uring_buf_ring_advance**(3)
call and a **io_uring_cq_advance**(3) into one operation. Since updating
either ring index entails a store memory barrier, doing both at once is
more efficient.

The **\_\_io_uring_buf_ring_cq_advance**(3) function performs the same
operation, except it splits the counts into two separate values. It
advances the CQ ring by *cq_count* entries, and the buffer ring by
*buf_count* entries rather than increment both by the same value.

# RETURN VALUE

None

# SEE ALSO

[io_uring_register_buf_ring], [io_uring_buf_ring_add],
[io_uring_buf_ring_advance]
