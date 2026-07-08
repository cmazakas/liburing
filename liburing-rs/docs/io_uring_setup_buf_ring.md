Setup and register buffer ring for provided
buffers

# DESCRIPTION

The [io_uring_setup_buf_ring] function registers a shared buffer
ring to be used with provided buffers. For the request types that
support it, provided buffers are given to the ring and one is selected
by a request if it has **IOSQE_BUFFER_SELECT** set in the SQE *flags*,
when the request is ready to receive data. This allows both clear
ownership of the buffer lifetime, and a way to have more read/receive
type of operations in flight than buffers available.

The *ring* argument must be a pointer to the ring for which the provided
buffer ring is being registered, *nentries* is the number of entries
requested in the buffer ring. This argument must be a power-of 2 in
size, and can be up to 32768 in size. *bgid* is the chosen buffer group
ID, *flags* are modifier flags for the operation, and *\*err* is a
pointer to an integer for the error value if any part of the ring
allocation and registration fails.

The *flags* argument can be set to one of the following values:

**IOU_PBUF_RING_INC**  
The buffers in this ring can be incrementally consumed. With partial
consumption, each completion of a given buffer ID will continue where
the previous one left off, or from the start if no completions have been
seen yet. When more completions should be expected for a given buffer
ID, the CQE will have **IORING_CQE_F_BUF_MORE** set in the *flags*
member. Available since 6.12.

Under the covers, this function uses [io_uring_register_buf_ring]
to register the ring, and handles the allocation of the ring rather than
letting the application open code it.

To unregister and free a buffer group ID setup with this function, the
application must call [io_uring_free_buf_ring]**.**

Available since 5.19.

# RETURN VALUE

On success [io_uring_setup_buf_ring] returns a pointer to the
buffer ring. On failure it returns **NULL** and sets *\*err* to -errno.

# NOTES

Note that even if the kernel supports this feature, registering a
provided buffer ring may still fail with **-EINVAL** if the host is a
32-bit architecture and the memory being passed in resides in high
memory.

# SEE ALSO

[io_uring_register_buf_ring], [io_uring_buf_ring_init],
[io_uring_buf_ring_add], [io_uring_buf_ring_advance],
[io_uring_buf_ring_cq_advance]
