Unregister a previously registered buffer.
ring

# DESCRIPTION

The [io_uring_unregister_buf_ring] function unregisters a
previously registered shared buffer ring indicated by *bgid*.

# RETURN VALUE

On success [io_uring_unregister_buf_ring] returns 0. On failure it
returns **-errno**.

# SEE ALSO

[io_uring_register_buf_ring], io_uring_buf_ring_free
