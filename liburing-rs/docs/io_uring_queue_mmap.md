Mmap io_uring ring after setup.

# DESCRIPTION

The [io_uring_queue_mmap] function maps the io_uring ring file
descriptor *fd* into memory using the parameters in *p*. The resulting
ring is stored in *ring*.

This function is a helper for applications that need to customize the
ring setup process. Most applications should use
[io_uring_queue_init] or [io_uring_queue_init_params] instead,
which call [io_uring_setup] and this function automatically.

The *fd* argument should be a file descriptor returned by
[io_uring_setup], and *p* should contain the parameters returned by
the setup call.

# RETURN VALUE

Returns 0 on success, or a negative errno value on error.

# SEE ALSO

[io_uring_setup], [io_uring_queue_init],
[io_uring_queue_init_params], [io_uring_queue_exit]
