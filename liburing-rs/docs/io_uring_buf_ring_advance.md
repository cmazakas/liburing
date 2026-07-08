Advance index of provided buffer in buffer
ring

# DESCRIPTION

The [io_uring_buf_ring_advance] commits *count* previously added
buffers to the shared buffer ring *br*, making them visible to the
kernel and hence consumable. This passes ownership of the buffer to the
ring.

# RETURN VALUE

None

# SEE ALSO

[io_uring_register_buf_ring], [io_uring_buf_ring_add],
[io_uring_buf_ring_cq_advance]
