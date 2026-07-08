Get required memlock size for a ring

# DESCRIPTION

The [io_uring_mlock_size] function returns the required
**RLIMIT_MEMLOCK** memory size for an io_uring ring with *entries*
entries and the specified setup *flags*.

On newer kernels (5.12+), io_uring no longer requires any memlock memory
and this function will return 0. On older kernels (5.11 and prior), this
returns the required memory so that the caller can ensure that enough
**RLIMIT_MEMLOCK** space is available before setting up a ring.

For more control over the ring parameters, use
[io_uring_mlock_size_params] instead.

# RETURN VALUE

Returns the required memlock size in bytes on success, 0 if no memlock
is needed, or a negative errno value on error.

# SEE ALSO

[io_uring_mlock_size_params], [io_uring_memory_size],
[io_uring_queue_init], [getrlimit](https://man7.org/linux/man-pages/man2/getrlimit.2.html)
