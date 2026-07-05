Get probe information from an existing ring.

# DESCRIPTION

The [io_uring_get_probe_ring] function returns probe information
for the io_uring instance specified by *ring*. This allows the
application to determine which opcodes are supported by the kernel.

The returned probe structure and must be freed by the application using
[io_uring_free_probe] when no longer needed.

This function is similar to [io_uring_get_probe], except it uses an
existing ring instead of creating a temporary one.

# RETURN VALUE

Returns a pointer to an allocated *struct io_uring_probe* on success, or
NULL on failure.

# SEE ALSO

[io_uring_get_probe], [io_uring_free_probe],
[io_uring_opcode_supported], [io_uring_register_probe]
