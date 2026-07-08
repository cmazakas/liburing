Calculate buffer ring mask size

# DESCRIPTION

[io_uring_buf_ring_mask] calculates the appropriate size mask for a
buffer ring. *ring_entries* is the ring entries as specified in
[io_uring_register_buf_ring]**.**

# RETURN VALUE

Size mask for the buffer ring.

# SEE ALSO

[io_uring_register_buf_ring], [io_uring_buf_ring_add]
