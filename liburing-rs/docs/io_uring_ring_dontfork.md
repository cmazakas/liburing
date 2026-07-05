Prevent ring memory from being shared after fork.

# DESCRIPTION

The [io_uring_ring_dontfork] function ensures that the mmap'ed
rings for the io_uring instance *ring* are not available to a child
process after a [fork](https://man7.org/linux/man-pages/man2/fork.2.html).

This function uses [madvise](https://man7.org/linux/man-pages/man2/madvise.2.html) with **MADV_DONTFORK** on the mmap'ed
ranges to prevent them from being shared with child processes. This is
useful when the parent wants exclusive access to the ring and doesn't
want the child to be able to access or interfere with it.

# RETURN VALUE

Returns 0 on success. On error, a negative errno value is returned.

# SEE ALSO

[io_uring_queue_init], [madvise](https://man7.org/linux/man-pages/man2/madvise.2.html), [fork](https://man7.org/linux/man-pages/man2/fork.2.html)
