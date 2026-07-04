Initialise a buffer ring.

# DESCRIPTION

**io_uring_buf_ring_init**(3) initialises *br* so that it is ready to be
used. It may be called after **io_uring_register_buf_ring**(3) but must
be called before the buffer ring is used in any other way.

# RETURN VALUE

None

# NOTES

Unless manual setup is needed, it's recommended to use
**io_uring_setup_buf_ring**(3) as it provides a simpler way to setup a
provided buffer ring.

# SEE ALSO

[io_uring_register_buf_ring], [io_uring_setup_buf_ring],
[io_uring_buf_ring_add], [io_uring_buf_ring_advance],
[io_uring_buf_ring_cq_advance]
