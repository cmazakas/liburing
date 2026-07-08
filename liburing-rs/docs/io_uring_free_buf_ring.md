Register and free a buffer ring for provided
buffers

# DESCRIPTION

The [io_uring_free_buf_ring] function unregisters a previously
registered shared buffer ring. The ring must have heen previously
returned from [io_uring_setup_buf_ring]**.**

The *ring* argument must pointer to the ring for which the provided
buffer ring is being registered, *br* must point to a buffer ring
previously returned by [io_uring_setup_buf_ring]**,** *nentries* is
the number of entries requested in the buffer ring, and *bgid* is the
buffer group ID that *br* was setup with.

Under the covers, this function uses [io_uring_unregister_buf_ring]
to unregister the ring, and handles the freeing of the ring rather than
letting the application open code it.

Available since 5.19.

# RETURN VALUE

On success [io_uring_free_buf_ring] returns zero. On failure it
returns **-errno**.

# SEE ALSO

[io_uring_setup_buf_ring]
