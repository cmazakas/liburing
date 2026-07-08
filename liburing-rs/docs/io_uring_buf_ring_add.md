Add buffers to a shared buffer ring

# DESCRIPTION

The [io_uring_buf_ring_add] adds a new buffer to the shared buffer
ring *br*. The buffer address is indicated by *addr* and is of *len*
bytes of length. *bid* is the buffer ID, which will be returned in the
CQE. *mask* is the size mask of the ring, available from
[io_uring_buf_ring_mask]**.** *buf_offset* is the offset to insert
at from the current tail. If just one buffer is provided before the ring
tail is committed with [io_uring_buf_ring_advance] or
[io_uring_buf_ring_cq_advance], then *buf_offset* should be 0. If
buffers are provided in a loop before being committed, the *buf_offset*
must be incremented by one for each buffer added.

# RETURN VALUE

None

# NOTES

liburing (or the kernel, for that matter) doesn't care about what buffer
ID maps to what buffer, and in fact when recycling buffers after use,
the application is free to add a different buffer into the same buffer
ID location. All that matters is that the application knows what a given
buffer ID in time corresponds to in terms of virtual memory. There's no
liburing or kernel assumption that these mappings are persistent over
time, they can very well be different every time a given buffer ID is
added to the provided buffer ring.

Note that no uring functions can write more than INT_MAX bytes to a
buffer in a single call. For details, see the man pages for individual
functions.

# SEE ALSO

[io_uring_register_buf_ring], [io_uring_buf_ring_mask],
[io_uring_buf_ring_advance], [io_uring_buf_ring_cq_advance]
