Get required memlock size for a ring with.
params

# DESCRIPTION

The [io_uring_mlock_size_params] function returns the required
**RLIMIT_MEMLOCK** memory size for an io_uring ring with *entries*
entries and the parameters specified in *p*.

On newer kernels (5.12+), io_uring no longer requires any memlock memory
and this function will return 0. On older kernels (5.11 and prior), this
returns the required memory so that the caller can ensure that enough
**RLIMIT_MEMLOCK** space is available before setting up a ring.

This function provides more control than [io_uring_mlock_size] by
allowing the caller to specify full ring parameters including CQ size
via *p-\>cq_entries* when **IORING_SETUP_CQSIZE** is set in *p-\>flags*.

# RETURN VALUE

Returns the required memlock size in bytes on success, 0 if no memlock
is needed, or a negative errno value on error.

# SEE ALSO

[io_uring_mlock_size], [io_uring_memory_size_params],
[io_uring_queue_init_params], [getrlimit]
