Get memory size needed for a ring with.
params

# DESCRIPTION

The [io_uring_memory_size_params] function returns the total memory
size needed for an io_uring ring with *entries* entries and the
parameters specified in *p*.

This is useful for applications that want to pre-allocate memory for a
ring or want to know the memory footprint before creating a ring.

This function provides more control than [io_uring_memory_size] by
allowing the caller to specify full ring parameters including CQ size
via *p-\>cq_entries* when **IORING_SETUP_CQSIZE** is set in *p-\>flags*.

# RETURN VALUE

Returns the required memory size in bytes on success, or a negative
errno value on error.

**-EINVAL**\
Invalid entries value (0 or too large without IORING_SETUP_CLAMP).

# SEE ALSO

[io_uring_memory_size], [io_uring_mlock_size_params],
[io_uring_queue_init_params]
